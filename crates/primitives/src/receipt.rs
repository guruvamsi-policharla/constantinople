//! Transaction receipt types.
//!
//! This module defines the consensus receipt payload emitted after transaction execution.

use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;

/// Execution status recorded in a transaction receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum ReceiptStatus {
    /// The transaction executed successfully.
    Success = 0,
    /// The transaction executed and reverted.
    Revert = 1,
}

impl Write for ReceiptStatus {
    fn write(&self, buf: &mut impl BufMut) {
        (*self as u8).write(buf);
    }
}

impl FixedSize for ReceiptStatus {
    const SIZE: usize = 1;
}

impl Read for ReceiptStatus {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Success),
            1 => Ok(Self::Revert),
            other => Err(Error::InvalidEnum(other)),
        }
    }
}

/// A transaction execution receipt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Receipt<D: Digest> {
    /// The hash of the transaction payload.
    pub transaction_hash: D,
    /// The final execution status.
    pub status: ReceiptStatus,
    /// Return payload from the root callframe.
    pub return_data: Bytes,
}

impl<D: Digest> Receipt<D> {
    /// Creates a receipt.
    pub const fn new(transaction_hash: D, status: ReceiptStatus, return_data: Bytes) -> Self {
        Self {
            transaction_hash,
            status,
            return_data,
        }
    }

    /// Creates a reverted receipt.
    pub const fn revert(transaction_hash: D, return_data: Bytes) -> Self {
        Self::new(transaction_hash, ReceiptStatus::Revert, return_data)
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl<D: Digest + for<'a> arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'_> for Receipt<D> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            transaction_hash: u.arbitrary()?,
            status: u.arbitrary()?,
            return_data: Bytes::from(<Vec<u8> as arbitrary::Arbitrary>::arbitrary(u)?),
        })
    }
}

impl<D: Digest> Write for Receipt<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.transaction_hash.write(buf);
        self.status.write(buf);
        self.return_data.write(buf);
    }
}

impl<D: Digest> EncodeSize for Receipt<D> {
    fn encode_size(&self) -> usize {
        self.transaction_hash.encode_size()
            + self.status.encode_size()
            + self.return_data.encode_size()
    }
}

impl<D: Digest> Read for Receipt<D> {
    type Cfg = <Bytes as Read>::Cfg;

    fn read_cfg(buf: &mut impl Buf, return_data_cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            transaction_hash: D::read(buf)?,
            status: ReceiptStatus::read(buf)?,
            return_data: Bytes::read_cfg(buf, return_data_cfg)?,
        })
    }
}
