use ring::digest::{digest, SHA256};
use ssz_types::{BitList, VariableList};
use std::cmp;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use typenum::marker_traits::Unsigned;
use types::helper_functions_types::Error;
use types::{
    beacon_state::BeaconState, config::Config, consts::GENESIS_EPOCH, primitives::*, types::*,
};

use crate::{
    crypto::hash,
    math::{int_to_bytes, int_to_bytes_32},
    misc::*,
    predicates::is_active_validator,
};

pub fn get_current_epoch<C: Config>(state: &BeaconState<C>) -> Epoch {
    compute_epoch_at_slot::<C>(state.slot)
}

pub fn get_previous_epoch<C: Config>(state: &BeaconState<C>) -> Epoch {
    let current_epoch = get_current_epoch(state);

    if current_epoch > GENESIS_EPOCH {
        current_epoch - 1
    } else {
        GENESIS_EPOCH
    }
}

pub fn get_block_root<C: Config>(state: &BeaconState<C>, epoch: Epoch) -> Result<H256, Error> {
    get_block_root_at_slot(state, compute_start_slot_at_epoch::<C>(epoch))
}

pub fn get_block_root_at_slot<C: Config>(
    state: &BeaconState<C>,
    slot: Slot,
) -> Result<H256, Error> {
    if !(slot < state.slot && state.slot <= slot + C::SlotsPerHistoricalRoot::to_u64()) {
        return Err(Error::SlotOutOfRange);
    }
    match usize::try_from(slot % C::SlotsPerHistoricalRoot::to_u64()) {
        Err(_err) => Err(Error::IndexOutOfRange),
        Ok(id) => match state.block_roots.get(id) {
            None => Err(Error::IndexOutOfRange),
            Some(block_root) => Ok(*block_root),
        },
    }
}

pub fn get_randao_mix<C: Config>(state: &BeaconState<C>, epoch: Epoch) -> Result<H256, Error> {
    match usize::try_from(epoch % C::EpochsPerHistoricalVector::to_u64()) {
        Err(_err) => Err(Error::IndexOutOfRange),
        Ok(id) => Ok(state.randao_mixes[id]),
    }
}

pub fn get_active_validator_indices<C: Config>(
    state: &BeaconState<C>,
    epoch: Epoch,
) -> Vec<ValidatorIndex> {
    let mut active_validator_indices = Vec::new();
    for (i, v) in state.validators.iter().enumerate() {
        if is_active_validator(v, epoch) {
            active_validator_indices.push(i as ValidatorIndex);
        }
    }
    active_validator_indices
}

pub fn get_validator_churn_limit<C: Config>(state: &BeaconState<C>) -> Result<u64, Error> {
    let active_validator_indices = get_active_validator_indices(state, get_current_epoch(state));

    // todo: check for 0

    Ok(cmp::max(
        C::min_per_epoch_churn_limit(),
        active_validator_indices.len() as u64 / C::churn_limit_quotient(),
    ))
}

// check
pub fn get_seed<C: Config>(
    state: &BeaconState<C>,
    epoch: Epoch,
    domain_type: DomainType,
) -> Result<H256, Error> {
    let mix = get_randao_mix::<C>(
        state,
        epoch + C::EpochsPerHistoricalVector::to_u64() - C::min_seed_lookahead() - 1,
    )?;

    let mut seed: [u8; 44] = [0; 44];
    seed[0..4].copy_from_slice(&int_to_bytes_32(domain_type, 4));
    seed[4..12].copy_from_slice(&int_to_bytes(epoch, 8));
    seed[12..44].copy_from_slice(&mix[..]);

    let mut hash_bytes: [u8; 32] = [0; 32];
    hash_bytes[0..32].copy_from_slice(digest(&SHA256, &seed).as_ref());

    Ok(H256::from(hash_bytes))
}

pub fn get_beacon_proposer_index<C: Config>(
    state: &BeaconState<C>,
) -> Result<ValidatorIndex, Error> {
    let epoch = get_current_epoch(state);

    match get_seed::<C>(state, epoch, C::domain_beacon_proposer()) {
        Ok(seed) => {
            let mut combined = seed.as_bytes().to_vec();
            combined.append(&mut int_to_bytes(state.slot, 8));

            let seed_combined = H256::from_slice(&hash(&combined)[0..32]);
            let indices = get_active_validator_indices(state, epoch);

            compute_proposer_index(state, &indices, &seed_combined)
        }
        Err(err) => Err(err),
    }
}

pub fn get_committee_count_at_slot<C: Config>(
    state: &BeaconState<C>,
    slot: Slot,
) -> Result<u64, Error> {
    let epoch = compute_epoch_at_slot::<C>(slot);
    Ok(cmp::max(
        1,
        cmp::min(
            C::max_committees_per_slot(),
            get_active_validator_indices(state, epoch).len() as u64
                / C::SlotsPerEpoch::to_u64()
                / C::target_committee_size(),
        ),
    ))
}

pub fn get_beacon_committee<C: Config>(
    state: &BeaconState<C>,
    slot: Slot,
    index: u64,
) -> Result<Vec<ValidatorIndex>, Error> {
    let epoch = compute_epoch_at_slot::<C>(slot);
    let committees_per_slot = get_committee_count_at_slot(state, slot)?;
    compute_committee::<C>(
        &get_active_validator_indices(state, epoch),
        &(get_seed(state, epoch, C::domain_beacon_attester())?),
        (slot % C::SlotsPerEpoch::to_u64()) * committees_per_slot + index,
        committees_per_slot * C::SlotsPerEpoch::to_u64(),
    )
}

pub fn get_total_balance<C: Config>(
    state: &BeaconState<C>,
    indices: &[ValidatorIndex],
) -> Result<u64, Error> {
    let mut sum = 0;
    for (_i, index) in indices.iter().enumerate() {
        match usize::try_from(*index) {
            Err(_err) => return Err(Error::IndexOutOfRange),
            Ok(id) => sum += state.validators[id].effective_balance,
        }
    }
    Ok(sum)
}

pub fn get_total_active_balance<C: Config>(state: &BeaconState<C>) -> Result<u64, Error> {
    get_total_balance::<C>(
        state,
        &get_active_validator_indices::<C>(state, get_current_epoch::<C>(state)),
    )
}

pub fn get_domain<C: Config>(
    state: &BeaconState<C>,
    domain_type: DomainType,
    message_epoch: Option<Epoch>,
) -> Domain {
    let epoch = message_epoch.unwrap_or_else(|| get_current_epoch(state));
    let fork_version = if epoch < state.fork.epoch {
        &state.fork.previous_version
    } else {
        &state.fork.current_version
    };
    compute_domain(domain_type, Some(fork_version))
}

pub fn get_indexed_attestation<C: Config>(
    state: &BeaconState<C>,
    attestation: &Attestation<C>,
) -> Result<IndexedAttestation<C>, Error> {
    let attesting_indices =
        get_attesting_indices(state, &attestation.data, &attestation.aggregation_bits)?;

    let mut vec: Vec<ValidatorIndex> = attesting_indices.iter().cloned().collect();
    vec.sort();

    Ok(IndexedAttestation {
        attesting_indices: VariableList::from(vec),
        data: attestation.data.clone(),
        signature: attestation.signature.clone(),
    })
}

pub fn get_attesting_indices<C: Config>(
    state: &BeaconState<C>,
    data: &AttestationData,
    bits: &BitList<C::MaxValidatorsPerCommittee>,
) -> Result<BTreeSet<ValidatorIndex>, Error> {
    let committee = get_beacon_committee(state, data.slot, data.index)?;
    if bits.len() != committee.len() {
        return Err(Error::AttestationBitsInvalid);
    }
    let mut attesting_indices = BTreeSet::new();
    for (i, index) in committee.iter().enumerate() {
        if bits.get(i).is_ok() {
            attesting_indices.insert(*index);
        }
    }
    Ok(attesting_indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::{FixedVector, VariableList};
    use types::config::MainnetConfig;
    use types::types::{Fork, Validator};

    #[test]
    fn test_get_current_epoch() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 33,
            ..BeaconState::default()
        };
        assert_eq!(get_current_epoch::<MainnetConfig>(&bs), 1);
    }

    #[test]
    fn test_get_previous_epoch() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 65,
            ..BeaconState::default()
        };
        assert_eq!(get_previous_epoch(&bs), 1);
    }

    #[test]
    fn test_get_previous_epoch_genesis() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 0,
            ..BeaconState::default()
        };
        assert_eq!(get_previous_epoch(&bs), MainnetConfig::genesis_epoch());
    }

    #[test]
    fn test_get_block_root() {
        let mut block_roots_vec = Vec::new();

        for x in 0..128 {
            block_roots_vec.push(H256::from([x; 32]));
        }

        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 128,
            block_roots: FixedVector::from(block_roots_vec),
            ..BeaconState::default()
        };

        assert_eq!(get_block_root(&bs, 3), Ok(H256::from([96; 32])));
    }

    #[test]
    fn test_get_seed() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            randao_mixes: FixedVector::from(vec![H256::from([1; 32]), H256::from([2; 32])]),
            ..BeaconState::default()
        };

        let actual = get_seed::<MainnetConfig>(&bs, 1, 1_u32);

        let expected = H256::from([
            0x14, 0x81, 0x4a, 0x14, 0x7c, 0x51, 0x6b, 0x2a, 0xc3, 0xda, 0xe0, 0x72, 0xea, 0xf9,
            0xd5, 0xca, 0x2e, 0x3a, 0xbd, 0xca, 0x96, 0x96, 0xd2, 0x44, 0x31, 0x3c, 0x35, 0x12,
            0x99, 0x33, 0xe3, 0x36,
        ]);

        assert_eq!(actual, Ok(expected));
    }

    #[test]
    fn test_get_block_root_at_slot() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 2,
            block_roots: FixedVector::from(vec![H256::from([0; 32]), H256::from([1; 32])]),
            ..BeaconState::default()
        };
        assert_eq!(get_block_root_at_slot(&bs, 1), Ok(H256::from([1; 32])));
    }

    #[test]
    fn test_get_block_root_at_slot_slot_equals_beacon_state_slot() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 0,
            ..BeaconState::default()
        };
        assert_eq!(
            get_block_root_at_slot(&bs, 0).err(),
            Some(Error::SlotOutOfRange),
        );
    }

    #[test]
    fn test_get_randao_mix() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            randao_mixes: FixedVector::from(vec![
                H256::from([5; 32]),
                H256::from([5; 32]),
                H256::from([5; 32]),
            ]),
            ..BeaconState::default()
        };

        assert_eq!(get_randao_mix(&bs, 2), Ok(H256::from([5; 32])))
    }

    #[test]
    fn test_get_active_validator_indices() {
        let v1 = Validator {
            activation_epoch: 1,
            exit_epoch: 2,
            ..Validator::default()
        };
        let v2 = Validator {
            activation_epoch: 0,
            exit_epoch: 1,
            ..Validator::default()
        };
        let bs: BeaconState<MainnetConfig> = BeaconState {
            validators: VariableList::from(vec![v1, v2]),
            ..BeaconState::default()
        };
        assert_eq!(get_active_validator_indices(&bs, 0), vec![1]);
    }

    #[test]
    fn test_get_validator_churn_limit() {
        let v1 = Validator {
            effective_balance: 11,
            activation_epoch: 0,
            exit_epoch: 2,
            ..Validator::default()
        };
        let bs: BeaconState<MainnetConfig> = BeaconState {
            validators: VariableList::from(vec![v1]),
            ..BeaconState::default()
        };

        assert_eq!(
            get_validator_churn_limit(&bs),
            Ok(MainnetConfig::min_per_epoch_churn_limit())
        )
    }

    #[test]
    fn test_get_active_balance() {
        let v1 = Validator {
            effective_balance: 11,
            activation_epoch: 0,
            exit_epoch: 2,
            ..Validator::default()
        };
        let v2 = Validator {
            effective_balance: 7,
            activation_epoch: 0,
            exit_epoch: 1,
            ..Validator::default()
        };
        let v3 = Validator {
            effective_balance: 5,
            activation_epoch: 0,
            exit_epoch: 1,
            ..Validator::default()
        };
        let bs: BeaconState<MainnetConfig> = BeaconState {
            validators: VariableList::from(vec![v1, v2, v3]),
            ..BeaconState::default()
        };

        assert_eq!(get_total_balance(&bs, &[0, 2]), Ok(16_u64))
    }

    #[test]
    fn test_get_total_active_balance() {
        let v1 = Validator {
            effective_balance: 10,
            activation_epoch: 0,
            exit_epoch: 2,
            ..Validator::default()
        };
        let v2 = Validator {
            effective_balance: 2,
            activation_epoch: 0,
            exit_epoch: 1,
            ..Validator::default()
        };
        let bs: BeaconState<MainnetConfig> = BeaconState {
            validators: VariableList::from(vec![v1, v2]),
            ..BeaconState::default()
        };

        assert_eq!(get_total_active_balance(&bs), Ok(12_u64))
    }

    #[test]
    fn test_get_domain_previous_version() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            fork: Fork {
                previous_version: [0, 0, 0, 1].into(),
                current_version: [0, 0, 1, 0].into(),
                epoch: 2,
            },
            ..BeaconState::default()
        };
        let domain_type: DomainType = 2_u32;
        let expected: u64 = 0x0100_0000_0000_0002_u64;

        assert_eq!(
            get_domain::<MainnetConfig>(&bs, domain_type, Some(1)),
            expected
        );
    }

    #[test]
    fn test_get_domain_current_version() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            fork: Fork {
                previous_version: [0, 0, 0, 1].into(),
                current_version: [0, 0, 1, 0].into(),
                epoch: 1,
            },
            ..BeaconState::default()
        };
        let domain_type: DomainType = 2_u32;
        let expected: u64 = 0x0001_0000_0000_0002_u64;

        assert_eq!(
            get_domain::<MainnetConfig>(&bs, domain_type, Some(1)),
            expected
        );
    }

    #[test]
    fn test_get_domain_default_version() {
        let bs: BeaconState<MainnetConfig> = BeaconState {
            slot: 9,
            fork: Fork {
                previous_version: [0, 0, 0, 1].into(),
                current_version: [0, 0, 1, 0].into(),
                epoch: 2,
            },
            ..BeaconState::default()
        };
        let domain_type: DomainType = 2_u32;
        let expected: u64 = 0x0100_0000_0000_0002_u64;

        assert_eq!(
            get_domain::<MainnetConfig>(&bs, domain_type, None),
            expected
        );
    }

    #[test]
    fn test_get_indexed_attestation() {
        let validator = Validator {
            activation_epoch: 0,
            exit_epoch: u64::max_value(),
            ..Validator::default()
        };
        let bs: BeaconState<MainnetConfig> = BeaconState {
            validators: VariableList::from(vec![validator; 2048]),
            randao_mixes: FixedVector::from(vec![H256::from([5; 32]); 64]),
            ..BeaconState::<MainnetConfig>::default()
        };

        let aggregation_bits = BitList::with_capacity(64).expect("BitList creation failed");

        let attestation: Attestation<MainnetConfig> = Attestation {
            aggregation_bits,
            data: AttestationData::default(),
            signature: AggregateSignatureBytes::default(),
        };

        let indices = vec![
            54, 57, 74, 136, 383, 406, 438, 440, 505, 509, 513, 519, 527, 549, 660, 672, 676, 682,
            704, 722, 728, 742, 774, 777, 787, 800, 822, 830, 896, 910, 916, 956, 997, 1016, 1041,
            1052, 1060, 1091, 1181, 1220, 1268, 1295, 1401, 1448, 1454, 1495, 1571, 1646, 1649,
            1699, 1708, 1734, 1743, 1786, 1794, 1807, 1830, 1835, 1875, 1899, 1910, 1921, 1974,
            2038,
        ];

        let expected: IndexedAttestation<MainnetConfig> = IndexedAttestation {
            attesting_indices: VariableList::from(indices),
            ..IndexedAttestation::default()
        };
        let actual = get_indexed_attestation(&bs, &attestation);

        assert_eq!(actual, Ok(expected));
    }
}
