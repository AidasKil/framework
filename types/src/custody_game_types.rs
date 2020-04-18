use serde::{Deserialize, Serialize};
use ssz_new_derive::{SszDecode, SszEncode};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use crate::{config::Config, primitives::*};
use std::ptr::null;
use crate::types::Attestation;
use bls::PublicKeyBytes;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct CustodySlashing<C: Config>{
    pub data_index: u64,
    pub malefactor_index: ValidatorIndex,
    pub malefactor_secret: SignatureBytes,
    pub whistleblower_index: ValidatorIndex,
    //pub shard_transition: ShardTransition TODO: can't find this, prob eth2.0 thing
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
pub struct EarlyDerivedSecretReveal<C: Config>{
    pub revealed_index: ValidatorIndex,
    pub epoch: Epoch,
    pub reveal: SignatureBytes,
    pub masker_index: ValidatorIndex,
    pub mask: FixedVector<u8, C::EarlyDerivedSecretRevealMaskSize>
}

impl Default for CustodyKeyReveal{
    fn default() -> Self {
        Self {
            revealer_index: ValidatorIndex::default(),
            reveal: SignatureBytes::empty()
        }
    }
}

impl<C: Config> Default for EarlyDerivedSecretReveal<C>{
    fn default() -> Self {
        Self {
            revealed_index: ValidatorIndex::default(),
            epoch: Epoch::default(),
            reveal: SignatureBytes::empty(),
            masker_index: ValidatorIndex::default(),
            mask: FixedVector::default()
        }
    }
}