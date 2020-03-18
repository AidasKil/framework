use eth2_hashing::ZERO_HASHES;
use types::primitives::H256;

pub fn hash(bytes: impl AsRef<[u8]>) -> H256 {
    H256::from_slice(eth2_hashing::hash(bytes.as_ref()).as_slice())
}

pub fn concatenate_and_hash(left: impl AsRef<[u8]>, right: impl AsRef<[u8]>) -> H256 {
    H256(eth2_hashing::hash32_concat(left.as_ref(), right.as_ref()))
}

// This will panic if called with a `height` greater than `eth2_hashing::ZERO_HASHES_MAX_INDEX`.
// That should not happen in normal operation.
pub fn zero_hash(height: usize) -> H256 {
    H256::from_slice(ZERO_HASHES[height].as_slice())
}

// `function`               | `function(1)`
// ------------------------ | --------------------------------------------------------------------
// `H256::from_low_u64_le`  | `0x0000000000000000000000000000000000000000000000000100000000000000`
// `hashing::hash_from_u64` | `0x0100000000000000000000000000000000000000000000000000000000000000`
pub fn hash_from_u64(number: u64) -> H256 {
    let mut h256 = H256::zero();
    h256[..core::mem::size_of::<u64>()].copy_from_slice(&number.to_le_bytes());
    h256
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use typenum::Unsigned as _;
    use types::consts::DepositContractTreeDepth;

    use super::*;

    #[test]
    fn zero_hash_calculates_31st_hash_correctly() {
        // `zero_hash(31)` is the highest-numbered hash that should be used in normal operation
        // (with `DEPOSIT_CONTRACT_TREE_DEPTH` equal to 32).
        assert_eq!(
            zero_hash(DepositContractTreeDepth::USIZE - 1),
            hex!("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7").into(),
        );
    }
}
