use serde::{Deserialize, Serialize};
use ssz_new_derive::{SszDecode, SszEncode};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use crate::{config::Config, primitives::*};
use std::ptr::null;
use crate::types::Attestation;
use bls::PublicKeyBytes;
use crate::beacon_chain_types::ShardTransition;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct CustodySlashing<C: Config>{
    pub data_index: u64,
    pub malefactor_index: ValidatorIndex,
    pub malefactor_secret: SignatureBytes,
    pub whistleblower_index: ValidatorIndex,
    pub shard_transition: ShardTransition<C>,
    pub attestation: Attestation<C>,
    pub data: VariableList<u8, C::MaxShardBlockSize>
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct SignedCustodySlashing<C: Config>{
    pub message: CustodySlashing<C>,
    pub signature: SignatureBytes
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct CustodyKeyReveal{
    pub revealer_index: ValidatorIndex,
    pub reveal: SignatureBytes
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct EarlyDerivedSecretReveal{
    pub revealed_index: ValidatorIndex,
    pub epoch: Epoch,
    pub reveal: SignatureBytes,
    pub masker_index: ValidatorIndex,
    pub mask: H256
}

impl Default for CustodyKeyReveal{
    fn default() -> Self {
        Self {
            revealer_index: ValidatorIndex::default(),
            reveal: SignatureBytes::empty()
        }
    }
}

impl Default for EarlyDerivedSecretReveal{
    fn default() -> Self {
        Self {
            revealed_index: ValidatorIndex::default(),
            epoch: Epoch::default(),
            reveal: SignatureBytes::empty(),
            masker_index: ValidatorIndex::default(),
            mask: H256::default()
        }
    }
}