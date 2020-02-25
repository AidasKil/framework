use core::{convert::TryFrom, ops::Index};

use derive_more::Display;
use ethereum_types::{H32, H64};
use serde::{Deserialize, Serialize};
use ssz_new::{SszDecode, SszDecodeError, SszEncode};
use ssz_new_derive::{SszDecode, SszEncode};
use tree_hash::{TreeHash, TreeHashType};
use tree_hash_derive::TreeHash;

pub use bls::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
pub use bls::{PublicKeyBytes, SignatureBytes};
pub use ethereum_types::H256;

pub type AggregateSignatureBytes = SignatureBytes;
pub type Epoch = u64;
pub type Gwei = u64;
pub type Shard = u64;
pub type Slot = u64;
pub type ValidatorIndex = u64;
pub type ValidatorId = PublicKey;
pub type DomainType = u32;
pub type UnixSeconds = u64;

// `ssz_static` tests contain YAML files that represent `Domain` and `Version` with strings of the
// form "0x…". Hash types from `ethereum-types` have the the `Deserialize` and `Serialize` impls we
// need, but `tree_hash` does not implement `TreeHash` for all of them, so we have wrap them and
// implement some traits ourselves.

type VersionAsArray = [u8; 4];

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Display, Deserialize, Serialize)]
#[display(fmt = "{}", _0)]
pub struct Version(H32);

impl Version {
    pub fn as_array(&self) -> &VersionAsArray {
        self.0.as_fixed_bytes()
    }
}

impl From<VersionAsArray> for Version {
    fn from(array: VersionAsArray) -> Self {
        Self(array.into())
    }
}

impl From<Version> for VersionAsArray {
    fn from(version: Version) -> Self {
        version.0.to_fixed_bytes()
    }
}

impl Index<usize> for Version {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.as_array().index(index)
    }
}

impl SszDecode for Version {
    fn is_ssz_fixed_len() -> bool {
        <VersionAsArray as SszDecode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <VersionAsArray as SszDecode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszDecodeError> {
        VersionAsArray::from_ssz_bytes(bytes).map(Self::from)
    }
}

impl SszEncode for Version {
    fn is_ssz_fixed_len() -> bool {
        <VersionAsArray as SszEncode>::is_ssz_fixed_len()
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.as_array().as_ssz_bytes()
    }
}

impl TreeHash for Version {
    fn tree_hash_type() -> TreeHashType {
        VersionAsArray::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.as_array().tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        VersionAsArray::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        self.as_array().tree_hash_root()
    }
}

type DomainAsInteger = u64;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize)]
pub struct Domain(H64);

impl Domain {
    pub fn to_integer(&self) -> DomainAsInteger {
        self.0.to_low_u64_le()
    }
}

impl From<DomainAsInteger> for Domain {
    fn from(integer: DomainAsInteger) -> Self {
        Self(H64::from_low_u64_le(integer))
    }
}

impl SszDecode for Domain {
    fn is_ssz_fixed_len() -> bool {
        <DomainAsInteger as SszDecode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <DomainAsInteger as SszDecode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszDecodeError> {
        DomainAsInteger::from_ssz_bytes(bytes).map(Self::from)
    }
}

impl SszEncode for Domain {
    fn is_ssz_fixed_len() -> bool {
        <DomainAsInteger as SszEncode>::is_ssz_fixed_len()
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.to_integer().as_ssz_bytes()
    }
}

impl TreeHash for Domain {
    fn tree_hash_type() -> TreeHashType {
        DomainAsInteger::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.to_integer().tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        DomainAsInteger::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        self.to_integer().tree_hash_root()
    }
}
