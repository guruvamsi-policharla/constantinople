//! Account model for the Constantinople chain.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use derive_more::{Debug, Display};

/// Default starting balance for accounts that have not been written yet.
pub const DEFAULT_ACCOUNT_BALANCE: u64 = 100;

/// An account, as represented in the state of the chain.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[display("Account {{ balance: {}, nonce: {} }}", balance, nonce)]
pub struct Account {
    /// The balance of the account, which is the amount of tokens that the
    /// account holds.
    pub balance: u64,
    /// The nonce of the account, which is incremented every time a
    /// transaction is sent from the account.
    pub nonce: u64,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            balance: DEFAULT_ACCOUNT_BALANCE,
            nonce: 0,
        }
    }
}

impl FixedSize for Account {
    const SIZE: usize = u64::SIZE + u64::SIZE;
}

impl Write for Account {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.nonce.write(buf);
    }
}

impl Read for Account {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            balance: u64::read(buf)?,
            nonce: u64::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, FixedSize};

    #[test]
    fn account_codec_roundtrip() {
        let account = Account {
            balance: 42,
            nonce: 7,
        };

        let mut buf = Vec::with_capacity(Account::SIZE);
        account.write(&mut buf);
        assert_eq!(buf.len(), Account::SIZE);

        let decoded = Account::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, account);
    }

    #[test]
    fn account_default_starts_funded() {
        assert_eq!(
            Account::default(),
            Account {
                balance: DEFAULT_ACCOUNT_BALANCE,
                nonce: 0,
            }
        );
    }
}
