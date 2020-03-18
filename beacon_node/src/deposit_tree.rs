use core::convert::TryInto as _;

use anyhow::{ensure, Result};
use helper_functions::crypto;
use thiserror::Error;
use typenum::Unsigned as _;
use types::{
    consts::DepositContractTreeDepth,
    fixed_vector,
    primitives::{DepositIndex, DepositProof, H256},
    types::DepositData,
};

use crate::hashing;

const DEPTH: usize = DepositContractTreeDepth::USIZE;
const MAX_DEPOSITS: DepositIndex = 1 << DEPTH;

#[derive(Debug, Error)]
#[error("deposit tree is full")]
struct Error;

// We do not store the whole deposit tree, only hashes that are enough to construct the proof.
// These implementations appear to use the same algorithm:
// - <https://github.com/ethereum/research/blob/2a94a123efab844662da3be9a086c9b944fbab9c/beacon_chain_impl/progressive_merkle_tree.py>
// - <https://github.com/ethereum/eth2.0-specs/blob/f4e883e0b30f073e258a43c1fddc8f4fdabd3faf/deposit_contract/contracts/validator_registration.vy>
#[derive(Default)]
pub struct DepositTree {
    deposit_count: DepositIndex,
    sibling_hashes: [H256; DEPTH],
}

impl DepositTree {
    pub fn add_deposit(&mut self, deposit_data: &DepositData) -> Result<(DepositProof, H256)> {
        ensure!(self.deposit_count < MAX_DEPOSITS, Error);

        let index = self.deposit_count;

        // We need to update one item in `self.sibling_hashes` every time we add a deposit.
        // `trailing_zeros` is the position of that item. See <https://oeis.org/A007814>.
        let trailing_zeros = (index + 1).trailing_zeros().try_into()?;

        let mut proof = fixed_vector::default();
        let mut hash = crypto::hash_tree_root(deposit_data);

        for height in 0..trailing_zeros {
            proof[height] = self.sibling_hashes[height];
            hash = hashing::concatenate_and_hash(proof[height], hash);
        }

        let updated_hash = hash;

        for height in trailing_zeros..DEPTH {
            if bit(index, height) {
                proof[height] = self.sibling_hashes[height];
                hash = hashing::concatenate_and_hash(proof[height], hash);
            } else {
                proof[height] = hashing::zero_hash(height);
                hash = hashing::concatenate_and_hash(hash, proof[height]);
            }
        }

        // This is what the specification calls `mix_in_length`.
        // See <https://github.com/ethereum/eth2.0-specs/blob/f4e883e0b30f073e258a43c1fddc8f4fdabd3faf/ssz/simple-serialize.md#merkleization>.
        proof[DEPTH] = hashing::hash_from_u64(index + 1);
        hash = hashing::concatenate_and_hash(hash, proof[DEPTH]);

        self.deposit_count += 1;
        if trailing_zeros < DEPTH {
            self.sibling_hashes[trailing_zeros] = updated_hash;
        }

        Ok((proof, hash))
    }
}

// There is a crate for this, of course. See <https://crates.io/crates/bit_field>.
const fn bit(number: u64, position: usize) -> bool {
    number & (1 << position) > 0
}

#[cfg(test)]
mod add_deposit_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::types::Deposit;

    use super::*;

    #[test]
    fn fails_when_tree_is_full() {
        let mut full_tree = DepositTree {
            deposit_count: MAX_DEPOSITS,
            ..DepositTree::default()
        };

        assert!(full_tree.add_deposit(&DepositData::default()).is_err());
    }

    #[test_resources("eth2.0-spec-tests/tests/*/phase0/genesis/initialization/*/*")]
    fn constructs_proofs_identical_to_the_ones_in_specification_tests(case: Case) {
        let mut deposit_tree = DepositTree::default();

        for Deposit { proof, data } in case.iterator("deposits", case.meta().deposits_count) {
            let (actual_proof, _) = deposit_tree
                .add_deposit(&data)
                .expect("no test cases have enough deposits to fill the tree");
            assert_eq!(actual_proof, proof);
        }
    }
}
