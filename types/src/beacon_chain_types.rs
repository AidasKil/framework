use bls::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use ssz_new_derive::{SszDecode, SszEncode};
use ssz_types::{BitList, FixedVector, VariableList};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::{Sum, U1};

pub use ethereum_types::H256;

use crate::{config::Config, primitives::*};
use crate::custody_game_types::{CustodyKeyReveal, EarlyDerivedSecretReveal, CustodySlashing};
// WIP: all of this should be moved to types.rs

// WIP: inconsistent usage. Should either pick Root or H256 and stick with it.
pub type Root = H256;

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct ShardTransition<C: Config> {
    pub start_slot: Slot,
    pub shard_block_lengths: VariableList<u64, C::MaxShardBlocksPerAttestation>,
    pub shard_data_roots: VariableList<H256, C::MaxShardBlocksPerAttestation>,
    pub shard_states: VariableList<ShardState, C::MaxShardBlocksPerAttestation>,
    pub proposer_signature_aggregate: SignatureBytes
}

impl<C: Config> Default for ShardTransition<C> {
    fn default() -> Self {
        Self {
            start_slot: Default::default(),
            shard_block_lengths: Default::default(),
            shard_data_roots: Default::default(),
            shard_states: Default::default(),
            proposer_signature_aggregate: SignatureBytes::empty()
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct ShardState {
    pub slot: Slot,
    pub gasprice: Gwei,
    pub transition_digest: H256,
    pub latest_block_root: Root
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct ShardBlock<C: Config> {
    pub shard_parent_root: Root,
    pub beacon_parent_root: Root,
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub body: VariableList<u8, C::MaxShardBlockSize>
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct SignedShardBlock<C: Config> {
    pub message: ShardBlock<C>,
    pub signature: SignatureBytes
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct ShardBlockHeader {
    pub shard_parent_root: Root,
    pub beacon_parent_root: Root,
    pub slot: Slot,
    pub proposer_index: ValidatorIndex,
    pub body_root: Root
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct CompactCommittee<C: Config> {
    pub pubkeys: VariableList<PublicKeyBytes, C::MaxValidatorsPerCommittee>,
    pub compact_validators: VariableList<u64, C::MaxValidatorsPerCommittee>
}

impl<C: Config> Default for CompactCommittee<C> {
    fn default() -> Self {
        Self {
            pubkeys: Default::default(),
            compact_validators: Default::default()
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, SszEncode, SszDecode, TreeHash)]
pub struct AttestationCustodyBitWrapper {
    pub attestation_data_root: Root,
    pub block_index: u64,
    pub bit: bool
}
