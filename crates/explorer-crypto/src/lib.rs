//! Browser crypto bindings for the explorer.

use commonware_codec::DecodeExt as _;
use commonware_cryptography::{Signer as _, ed25519};
use wasm_bindgen::prelude::*;

const ED25519_PRIVATE_KEY_BYTES: usize = 32;

/// A Constantinople Ed25519 account key.
#[wasm_bindgen]
pub struct ChainKey {
    private_key: ed25519::PrivateKey,
}

#[wasm_bindgen]
impl ChainKey {
    /// Builds an account key from 32 private-key bytes.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<Self, JsError> {
        if seed.len() != ED25519_PRIVATE_KEY_BYTES {
            return Err(JsError::new("Ed25519 seed must be 32 bytes"));
        }

        let private_key = ed25519::PrivateKey::decode(seed)
            .map_err(|error| JsError::new(&format!("invalid Ed25519 seed: {error}")))?;
        Ok(Self { private_key })
    }

    /// Returns the public key bytes for this account.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.private_key.public_key().as_ref().to_vec()
    }

    /// Signs `message` with Commonware's namespaced Ed25519 signer.
    pub fn sign(&self, namespace: &[u8], message: &[u8]) -> Vec<u8> {
        self.private_key.sign(namespace, message).as_ref().to_vec()
    }
}
