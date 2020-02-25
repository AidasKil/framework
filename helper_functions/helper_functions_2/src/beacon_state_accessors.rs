use crate::crypto::*;
use crate::math::*;
use crate::misc::*;
use crate::predicates::is_active_validator;
use ethereum_types::H256;
use ssz_types::BitList;
use std::cmp::max;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use typenum::Unsigned as _;
use types::beacon_state::BeaconState;
use types::config::Config;
use types::consts::*;
use types::helper_functions_types::Error;
use types::primitives::*;
use types::types::{Attestation, AttestationData, IndexedAttestation};

pub fn get_current_epoch<C: Config>(state: &BeaconState<C>) -> Epoch {
    compute_epoch_at_slot::<C>(state.slot)
}

pub fn get_previous_epoch<C: Config>(state: &BeaconState<C>) -> Epoch {
    let current_epoch = get_current_epoch(state);
    if current_epoch == 0 {
        current_epoch
    } else {
        current_epoch - 1
    }
}

pub fn get_block_root<C: Config>(state: &BeaconState<C>, epoch: Epoch) -> Result<H256, Error> {
    get_block_root_at_slot::<C>(state, compute_start_slot_at_epoch::<C>(epoch))
}

pub fn get_block_root_at_slot<C: Config>(
    state: &BeaconState<C>,
    slot: Slot,
) -> Result<H256, Error> {
    if !(slot < state.slot && state.slot <= slot + C::SlotsPerHistoricalRoot::U64) {
        return Err(Error::SlotOutOfRange);
    }

    let index =
        usize::try_from(slot % C::SlotsPerHistoricalRoot::U64).expect("Expected successfull cast");

    if index >= state.block_roots.len() {
        return Err(Error::IndexOutOfRange);
    }

    Ok(state.block_roots[index])
}

pub fn get_randao_mix<C: Config>(state: &BeaconState<C>, epoch: Epoch) -> Result<H256, Error> {
    let index = usize::try_from(epoch % C::EpochsPerHistoricalVector::U64)
        .expect("Expected successfull cast");
    if index >= state.randao_mixes.len() {
        return Err(Error::IndexOutOfRange);
    }

    Ok(state.randao_mixes[index])
}

// pub fn get_active_validator_indices<C: Config>(
//     _state: &BeaconState<C>,
//     _epoch: Epoch,
// ) -> impl Iterator<Item = &ValidatorIndex> {
//     [].iter()
// }
// pub fn get_active_validator_indices<C: Config>(
//     _state: &BeaconState<C>,
//     _epoch: Epoch,
// ) -> impl Iterator<Item = &ValidatorIndex> {
//     // // let mut validators = Vec::<ValidatorIndex>::new();
//     // // let mut vals = iter::<&ValidatorIndex>();
//     // let mut vals = [].iter();
//     // for (i, v) in _state.validators.iter().enumerate() {
//     //     if is_active_validator(v, _epoch) {
//     //         // validators.push(i as ValidatorIndex);
//     //         vals.chain(&[i as ValidatorIndex]);
//     //     }
//     // }
//     // // validators.iter()
//     // vals

//     _state.validators.iter().copied().filter(|v|
//     (v, _epoch))
// }

pub fn get_active_validator_indices<C: Config>(
    state: &BeaconState<C>,
    epoch: Epoch,
) -> Vec<ValidatorIndex> {
    let mut validators = Vec::<ValidatorIndex>::new();
    for (i, v) in state.validators.iter().enumerate() {
        if is_active_validator(v, epoch) {
            validators.push(i as ValidatorIndex);
        }
    }
    validators
}

pub fn get_validator_churn_limit<C: Config>(state: &BeaconState<C>) -> Result<u64, Error> {
    let active_validator_indices = get_active_validator_indices(state, get_current_epoch(state));
    let active_validator_count = active_validator_indices.len() as u64;
    Ok(max(
        C::min_per_epoch_churn_limit(),
        active_validator_count / C::churn_limit_quotient(),
    ))
}

pub fn get_seed<C: Config>(
    state: &BeaconState<C>,
    epoch: Epoch,
    domain_type: DomainType,
) -> Result<H256, Error> {
    let domain_bytes = int_to_bytes(domain_type.into(), 4);
    if domain_bytes.is_err() {
        return Err(domain_bytes.err().expect("Should be error"));
    }
    let domain_b = domain_bytes.expect("Expected valid conversion");

    let epoch_bytes = int_to_bytes(epoch, 8);
    if epoch_bytes.is_err() {
        return Err(epoch_bytes.err().expect("Should be error"));
    }
    let epoch_b = epoch_bytes.expect("Expected valid conversion");

    let mix = get_randao_mix(
        state,
        epoch + C::EpochsPerHistoricalVector::U64 - C::min_seed_lookahead() - 1,
    );
    if mix.is_err() {
        return Err(mix.err().expect("Should be error"));
    }

    let mut seed: [u8; 44] = [0; 44];
    seed[0..4].copy_from_slice(&domain_b[..]);
    seed[4..12].copy_from_slice(&epoch_b[..]);
    seed[12..44].copy_from_slice(&(mix.expect("Expected success"))[..]);

    Ok(H256::from_slice(&hash(&seed)))
}

pub fn get_committee_count_at_slot<C: Config>(
    state: &BeaconState<C>,
    slot: Slot,
) -> Result<u64, Error> {
    let epoch = compute_epoch_at_slot::<C>(slot);
    let active_count = get_active_validator_indices(state, epoch).len() as u64
        / C::SlotsPerEpoch::U64
        / C::target_committee_size();
    let mut count = if C::max_committees_per_slot() < active_count {
        C::max_committees_per_slot()
    } else {
        active_count
    };

    count = if 1 > count { 1 } else { count };

    Ok(count)
}

pub fn get_beacon_committee<C: Config>(
    state: &BeaconState<C>,
    slot: Slot,
    index: u64,
) -> Result<Vec<ValidatorIndex>, Error> {
    let epoch = compute_epoch_at_slot::<C>(slot);
    let committees_per_slot = get_committee_count_at_slot(state, slot);
    if committees_per_slot.is_err() {
        return Err(committees_per_slot.err().expect("Should be error"));
    }

    let indices = get_active_validator_indices(state, epoch);
    let seed = get_seed(state, epoch, C::domain_beacon_attester());
    if seed.is_err() {
        return Err(seed.err().expect("Should be error"));
    }

    let committees = committees_per_slot.expect("Expected seed");
    let i = (slot % C::SlotsPerEpoch::U64) * committees + index;
    let count = committees * C::SlotsPerEpoch::U64;

    compute_committee::<C>(indices.as_slice(), &seed.expect("Expected seed"), i, count)
}

pub fn get_beacon_proposer_index<C: Config>(
    state: &BeaconState<C>,
) -> Result<ValidatorIndex, Error> {
    let epoch = get_current_epoch(state);
    let seed = get_seed(state, epoch, C::domain_beacon_proposer());
    if seed.is_err() {
        return Err(seed.err().expect("Should be error"));
    }

    let indices = get_active_validator_indices(state, epoch);

    let mut seed_with_slot = [0; 40];
    seed_with_slot[..32].copy_from_slice(seed?.as_bytes());
    seed_with_slot[32..].copy_from_slice(&state.slot.to_le_bytes());
    let seed = H256::from_slice(hash(&seed_with_slot).as_slice());

    compute_proposer_index(state, &indices, &seed)
}

pub fn get_total_balance<C: Config>(
    state: &BeaconState<C>,
    indices: &[ValidatorIndex],
) -> Result<u64, Error> {
    let mut balance: Gwei = 0;
    for (i, v) in state.validators.iter().enumerate() {
        if indices.contains(&(i as u64)) {
            balance += v.effective_balance;
        }
    }
    if balance > 1 {
        Ok(balance)
    } else {
        Ok(1)
    }
}

pub fn get_total_active_balance<C: Config>(state: &BeaconState<C>) -> Result<u64, Error> {
    let current_epoch = get_current_epoch(state);
    get_total_balance(state, &get_active_validator_indices(state, current_epoch))
}

pub fn get_domain<C: Config>(
    state: &BeaconState<C>,
    domain_type: DomainType,
    message_epoch: Option<Epoch>,
) -> Domain {
    let epoch = if message_epoch == None {
        get_current_epoch(state)
    } else {
        message_epoch.expect("Expected a value")
    };
    let fork_version = if epoch < state.fork.epoch {
        state.fork.previous_version
    } else {
        state.fork.current_version
    };
    compute_domain(domain_type, Some(&fork_version))
}

pub fn get_indexed_attestation<C: Config>(
    state: &BeaconState<C>,
    attestation: &Attestation<C>,
) -> Result<IndexedAttestation<C>, Error> {
    let attesting_indices =
        get_attesting_indices(state, &attestation.data, &attestation.aggregation_bits)?;

    let att = IndexedAttestation {
        attesting_indices: attesting_indices.into_iter().collect::<Vec<_>>().into(),
        data: attestation.data.clone(),
        signature: attestation.signature.clone(),
    };
    Ok(att)
}

pub fn get_attesting_indices<C: Config>(
    state: &BeaconState<C>,
    attestation_data: &AttestationData,
    bitlist: &BitList<C::MaxValidatorsPerCommittee>,
) -> Result<BTreeSet<ValidatorIndex>, Error> {
    let comittee = get_beacon_committee(state, attestation_data.slot, attestation_data.index);
    if comittee.is_err() {
        return Err(comittee.err().expect("Expected success"));
    }
    let mut validators: BTreeSet<ValidatorIndex> = BTreeSet::new();
    for (i, v) in comittee
        .expect("Expected success getting committee")
        .into_iter()
        .enumerate()
    {
        if bitlist
            .get(i)
            .expect("bitfield length should match committee size")
        {
            validators.insert(v);
        }
    }
    Ok(validators)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::{typenum, FixedVector, VariableList};
    use types::config::MinimalConfig;
    use types::types::Validator;

    #[test]
    fn test_get_current_zero_epoch() {
        let state = BeaconState::<MinimalConfig>::default();
        assert_eq!(get_current_epoch::<MinimalConfig>(&state), 0);
    }

    #[test]
    fn test_get_current_epoch() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.slot = 35;
        assert_eq!(get_current_epoch::<MinimalConfig>(&state), 4);
    }

    #[test]
    fn test_get_previous_zero_epoch() {
        let state = BeaconState::<MinimalConfig>::default();
        assert_eq!(get_previous_epoch::<MinimalConfig>(&state), 0);
    }

    #[test]
    fn test_get_previous_epoch() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.slot = 35;
        assert_eq!(get_previous_epoch::<MinimalConfig>(&state), 3);
    }

    #[test]
    fn test_get_block_root() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.slot = 20;
        // let base: Vec<H256> = vec![H256::from([0; 32]), H256::from([1; 32])];
        let mut base: Vec<H256> = vec![];
        for x in 0..19 {
            base.push(H256::from([x; 32]));
        }
        let roots: FixedVector<_, typenum::U64> = FixedVector::from(base);
        state.block_roots = roots;
        let result = get_block_root::<MinimalConfig>(&state, 1);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.expect("Expected success"), H256::from([8; 32]));
    }

    #[test]
    fn test_get_block_root_at_slot() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.slot = 2;
        let base: Vec<H256> = vec![H256::from([0; 32]), H256::from([1; 32])];
        let roots: FixedVector<_, typenum::U64> = FixedVector::from(base);
        state.block_roots = roots;
        let result = get_block_root_at_slot::<MinimalConfig>(&state, 1);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.expect("Expected success"), H256::from([1; 32]));
    }

    #[test]
    fn test_get_randao_mix() {
        let mut state = BeaconState::<MinimalConfig>::default();
        let base: Vec<H256> = vec![H256::from([0; 32])];
        let mixes: FixedVector<_, typenum::U64> = FixedVector::from(base);
        state.randao_mixes = mixes;
        let result = get_randao_mix::<MinimalConfig>(&state, 0);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.expect("Expected success"), H256::from([0; 32]));
    }

    #[test]
    fn test_get_minimal_validator_churn_limit() {
        let state = BeaconState::<MinimalConfig>::default();
        let result = get_validator_churn_limit::<MinimalConfig>(&state);
        assert_eq!(
            result.expect("Expected min_per_epoch_churn_limit"),
            MinimalConfig::min_per_epoch_churn_limit()
        );
    }

    // churn_limit_quotient 0x0001_0000 -> 0x0000_0010
    // #[test]
    // fn test_get_validator_churn_limit() {
    //     let mut state = BeaconState::<MinimalConfig>::default();
    //     state.slot = 12;
    //     for x in 0..82 {
    //         let mut validator = Validator::default();
    //         validator.activation_epoch = 0;
    //         validator.exit_epoch = 10;
    //         state.validators.push(validator);
    //     }
    //     let result = get_validator_churn_limit::<MinimalConfig>(&state);
    //     assert_eq!(result.is_ok(), true);
    //     assert_eq!(result.expect("Expected success"), 5);
    // }

    #[test]
    fn test_get_total_minimal_balance() {
        let mut state = BeaconState::<MinimalConfig>::default();
        state.validators =
            VariableList::new([Validator::default()].to_vec()).expect("Expected success");
        let result = get_total_balance::<MinimalConfig>(&state, &[0]);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.expect("Expected success"), 1);
    }

    #[test]
    fn test_get_total_balance() {
        let mut state = BeaconState::<MinimalConfig>::default();
        let mut validator1 = Validator::default();
        validator1.effective_balance = 17;
        let mut validator2 = Validator::default();
        validator2.effective_balance = 15;
        let mut validator3 = Validator::default();
        validator3.effective_balance = 10;
        state.validators = VariableList::new([validator1, validator2, validator3].to_vec())
            .expect("Expected success");
        let result = get_total_balance::<MinimalConfig>(&state, &[0, 2]);
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.expect("Expected success"), 27);
    }

    #[test]
    fn test_get_active_validators() {
        let mut validator1 = Validator::default();
        validator1.activation_epoch = 0;
        validator1.exit_epoch = 10;
        let mut validator2 = Validator::default();
        validator2.activation_epoch = 0;
        validator2.exit_epoch = 1;
        let mut validator3 = Validator::default();
        validator3.activation_epoch = 0;
        validator3.exit_epoch = 10;

        let mut state = BeaconState::<MinimalConfig>::default();
        state.validators = VariableList::new([validator1, validator2, validator3].to_vec())
            .expect("Expected success");
        let result = get_active_validator_indices::<MinimalConfig>(&state, 3);
        assert_eq!(result, [0, 2].to_vec());
    }
}
