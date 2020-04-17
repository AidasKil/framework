use bls::{Signature};
use types::primitives::{Epoch, ValidatorIndex};
use types::types::Attestation;

//TODO: define
pub const MAX_SHARD_BLOCK_SIZE: u32 = 1024;

pub struct CustodySlashing{
    //Attestation.custody_bits_blocks[data_index][committee.index(malefactor_index)] is the target custody bit to check.
    pub data_index: u64,
    pub malefactor_index: ValidatorIndex,
    //pub malefactor_secret: Signature,
    pub whistleblower_index: ValidatorIndex,
    //(Attestation.data.shard_transition_root as ShardTransition).shard_data_roots[data_index] is the root of the data.
    //pub shard_transition: ShardTransition TODO: can't find this, prob eth2.0 thing
    //pub attestation: Attestation,
    pub data: Vec<i8> //size should be MAX_SHARD_BLOCK_SIZE
}

pub struct SignedCustodySlashing{
    pub message: CustodySlashing,
    pub signature: Signature
}

pub struct CustodyKeyReveal{
    //index of the validator whose key is being revealed
    pub revealer_index: ValidatorIndex,
    //Masked signature
    pub reveal: Signature
}

pub struct EarlyDerivedSecretReveal{
    pub revealed_index: ValidatorIndex,
    pub epoch: Epoch,
    pub reveal: Signature,
    pub masker_index: ValidatorIndex,
    //pub mask: Bytes32
}


