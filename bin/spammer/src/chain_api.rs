//! Minimal HTTP client for the relayer's health and account endpoints.
//!
//! The spammer assumes a fresh chain (all accounts at nonce zero with zero
//! private commitments) and an available relayer. These helpers let it verify
//! both assumptions before submitting, and reconcile a batch whose outcome was
//! lost to a transport failure against committed on-chain state.

use commonware_codec::Encode;
use commonware_cryptography::ed25519;
use commonware_formatting::hex;
use constantinople_primitives::{BalanceCommitment, DEFAULT_ACCOUNT_BALANCE, TransactionPublicKey};
use std::time::Duration;

/// How often readiness and reconciliation polls re-query the relayer.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Per-request timeout for health and account lookups.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// On-chain account state as served by `GET /account/{public_key}`.
#[derive(Debug, serde::Deserialize)]
pub struct AccountInfo {
    pub balance: u64,
    pub nonce: NonceInfo,
    pub private: String,
    pub pending: String,
}

/// Nonce state as served by the account endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct NonceInfo {
    pub base: u64,
    pub bitmap: u64,
}

/// Why an account lookup failed.
#[derive(Debug)]
pub enum AccountError {
    /// The node has not attached its state database yet (HTTP 503).
    NotReady,
    /// Transport failure or unexpected response.
    Unavailable(String),
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "state not attached yet"),
            Self::Unavailable(reason) => write!(f, "unavailable: {reason}"),
        }
    }
}

/// Client for the relayer's read-side endpoints.
#[derive(Clone)]
pub struct ChainApi {
    url: String,
    http: reqwest::Client,
}

impl ChainApi {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Polls `GET /health` until it returns 200 or `timeout` elapses.
    pub async fn wait_for_health(&self, timeout: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let response = self
                .http
                .get(format!("{}/health", self.url))
                .timeout(REQUEST_TIMEOUT)
                .send()
                .await;
            if matches!(&response, Ok(response) if response.status().is_success()) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "relayer at {} did not become healthy within {timeout:?}",
                    self.url
                ));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Fetches the committed account state; `Ok(None)` when the account has
    /// never been written (indistinguishable from a fresh default account).
    pub async fn account(
        &self,
        public_key: &ed25519::PublicKey,
    ) -> Result<Option<AccountInfo>, AccountError> {
        let key = TransactionPublicKey::ed25519(public_key.clone());
        let response = self
            .http
            .get(format!("{}/account/{}", self.url, hex(&key.encode())))
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|error| AccountError::Unavailable(error.to_string()))?;
        match response.status().as_u16() {
            200 => {
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| AccountError::Unavailable(error.to_string()))?;
                serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|error| AccountError::Unavailable(error.to_string()))
            }
            404 => Ok(None),
            503 => Err(AccountError::NotReady),
            other => Err(AccountError::Unavailable(format!("http status {other}"))),
        }
    }
}

/// Hex encoding of a commitment, matching the account endpoint's encoding.
pub fn commitment_hex(commitment: &BalanceCommitment) -> String {
    hex(commitment.as_bytes())
}

/// Whether the response describes an account indistinguishable from one the
/// chain has never touched.
pub fn is_pristine(info: &AccountInfo) -> bool {
    let zero = commitment_hex(&BalanceCommitment::zero());
    info.balance == DEFAULT_ACCOUNT_BALANCE
        && info.nonce.base == 0
        && info.nonce.bitmap == 0
        && info.private == zero
        && info.pending == zero
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(balance: u64, base: u64, bitmap: u64, private: &str, pending: &str) -> AccountInfo {
        AccountInfo {
            balance,
            nonce: NonceInfo { base, bitmap },
            private: private.to_string(),
            pending: pending.to_string(),
        }
    }

    #[test]
    fn pristine_accounts_are_recognized() {
        let zero = commitment_hex(&BalanceCommitment::zero());
        assert!(is_pristine(&info(
            DEFAULT_ACCOUNT_BALANCE,
            0,
            0,
            &zero,
            &zero
        )));
    }

    #[test]
    fn touched_accounts_are_rejected() {
        let zero = commitment_hex(&BalanceCommitment::zero());
        let one = commitment_hex(&BalanceCommitment::commit(1));
        assert!(!is_pristine(&info(
            DEFAULT_ACCOUNT_BALANCE,
            1,
            0,
            &zero,
            &zero
        )));
        assert!(!is_pristine(&info(
            DEFAULT_ACCOUNT_BALANCE,
            0,
            2,
            &zero,
            &zero
        )));
        assert!(!is_pristine(&info(99, 0, 0, &zero, &zero)));
        assert!(!is_pristine(&info(
            DEFAULT_ACCOUNT_BALANCE,
            0,
            0,
            &one,
            &zero
        )));
        assert!(!is_pristine(&info(
            DEFAULT_ACCOUNT_BALANCE,
            0,
            0,
            &zero,
            &one
        )));
    }

    #[tokio::test]
    async fn wait_for_health_succeeds_once_server_is_up() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // First connection: refuse with 503; second: healthy.
            for (i, status) in ["503 Service Unavailable", "200 OK"].iter().enumerate() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 1024];
                let _ = stream.read(&mut buffer).await;
                let response =
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
                drop(stream);
                let _ = i;
            }
        });

        let api = ChainApi::new(&format!("http://{addr}"));
        api.wait_for_health(Duration::from_secs(10))
            .await
            .expect("health should succeed after the second poll");
    }

    #[tokio::test]
    async fn wait_for_health_times_out_when_unreachable() {
        // Bind-then-drop to get a port nothing is listening on.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let api = ChainApi::new(&format!("http://{addr}"));
        let result = api.wait_for_health(Duration::from_millis(100)).await;
        assert!(result.is_err(), "unreachable relayer should time out");
    }
}
