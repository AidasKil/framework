use bls::Signature;
use serde::{Deserialize, Serialize};
use ssz_new_derive::{SszDecode, SszEncode};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use crate::{types::*};
use crate::{config::Config, primitives::*};
use std::ptr::null;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct CustodySlashing<C: Config>{
    pub data_index: u64,
    pub malefactor_index: ValidatorIndex,
    pub malefactor_secret: Signature,
    pub whistleblower_index: ValidatorIndex,
    //pub shard_transition: ShardTransition TODO: can't find this, prob eth2.0 thing
    pub attestation: Attestation<C>,
    pub data: VariableList<u8, C::MaxShardBlockSize>
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct SignedCustodySlashing<C: Config>{
    pub message: CustodySlashing<C>,
    pub signature: Signature
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct CustodyKeyReveal{
    pub revealer_index: ValidatorIndex,
    pub reveal: Signature
}
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct EarlyDerivedSecretReveal<C: Config>{
    pub revealed_index: ValidatorIndex,
    pub epoch: Epoch,
    pub reveal: Signature,
    pub masker_index: ValidatorIndex,
    pub mask: FixedVector<u8, C::EarlyDerivedSecretRevealMaskSize> //TODO: use config for mask size
}


impl Default for CustodyKeyReveal{
    fn default() -> Self {
        Self {
            revealer_index: ValidatorIndex::default(),
            reveal: Signature::empty_signature()
        }
    }
}

impl<C: Config> Default for EarlyDerivedSecretReveal<C>{
    fn default() -> Self {
        Self {
            revealed_index: ValidatorIndex::default(),
            epoch: Epoch::default(),
            reveal: Signature::empty_signature(),
            masker_index: ValidatorIndex::default(),
            mask: FixedVector::default()
        }
    }
}