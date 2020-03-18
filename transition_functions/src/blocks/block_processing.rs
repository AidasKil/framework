use helper_functions::beacon_state_accessors::*;
use helper_functions::beacon_state_mutators::*;
use helper_functions::crypto::{bls_verify, hash, hash_tree_root};
use helper_functions::math::*;
use helper_functions::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use helper_functions::predicates::{
    is_active_validator, is_slashable_attestation_data, is_slashable_validator,
    is_valid_merkle_branch, validate_indexed_attestation,
};
use std::collections::BTreeSet;
use std::convert::TryInto;
use typenum::Unsigned as _;
use types::consts::*;
use types::types::*;
use types::{
    beacon_state::*,
    config::{Config, MainnetConfig},
    types::VoluntaryExit,
};

pub fn process_block<T: Config>(state: &mut BeaconState<T>, block: &BeaconBlock<T>) {
    process_block_header(state, &block);
    process_randao(state, &block.body);
    process_eth1_data(state, &block.body);
    process_operations(state, &block.body);
}

fn process_voluntary_exit<T: Config>(
    state: &mut BeaconState<T>,
    signed_voluntary_exit: &SignedVoluntaryExit,
) {
    let voluntary_exit = &signed_voluntary_exit.message;
    let validator = &state.validators[voluntary_exit.validator_index as usize];
    // Verify the validator is active
    assert!(is_active_validator(&validator, get_current_epoch(state)));
    // Verify the validator has not yet exited
    assert!(validator.exit_epoch == FAR_FUTURE_EPOCH);
    // Exits must specify an epoch when they become valid; they are not valid before then
    assert!(get_current_epoch(state) >= voluntary_exit.epoch);
    // Verify the validator has been active long enough
    assert!(
        get_current_epoch(state) >= validator.activation_epoch + T::persistent_committee_period()
    );
    // Verify signature
    let domain = get_domain(
        state,
        T::domain_voluntary_exit() as u32,
        Some(voluntary_exit.epoch),
    );
    let signing_root = compute_signing_root(voluntary_exit, domain);
    assert!(bls_verify(
        &(bls::PublicKeyBytes::from_bytes(&validator.pubkey.as_bytes()).unwrap()),
        signing_root.as_bytes(),
        &(signed_voluntary_exit.signature.clone())
            .try_into()
            .unwrap(),
    )
    .unwrap());
    // Initiate exit
    initiate_validator_exit(state, voluntary_exit.validator_index).unwrap();
}

fn process_deposit<T: Config>(state: &mut BeaconState<T>, deposit: &Deposit) {
    //# Verify the Merkle branch  is_valid_merkle_branch

    assert!(is_valid_merkle_branch(
        &hash_tree_root(&deposit.data),
        &deposit.proof,
        DEPOSIT_CONTRACT_TREE_DEPTH + 1,
        state.eth1_deposit_index,
        &state.eth1_data.deposit_root
    )
    .unwrap());

    //# Deposits must be processed in order
    state.eth1_deposit_index += 1;

    let DepositData {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
    } = &deposit.data;

    for (index, v) in state.validators.iter().enumerate() {
        // bls::PublicKeyBytes::from_bytes(&v.pubkey.as_bytes()).unwrap()
        if bls::PublicKeyBytes::from_bytes(&v.pubkey.as_bytes()).unwrap() == *pubkey {
            //# Increase balance by deposit amount
            increase_balance(state, index as u64, *amount).unwrap();
            return;
        }
    }
    //# Verify the deposit signature (proof of possession) for new validators.
    //# Note: The deposit contract does not check signatures.
    //# Note: Deposits are valid across forks, thus the deposit domain is retrieved directly from `compute_domain`.
    let domain = compute_domain::<T>(T::domain_deposit(), None);
    let deposit_message = DepositMessage {
        pubkey: pubkey.clone(),
        withdrawal_credentials: *withdrawal_credentials,
        amount: *amount,
    };
    let signing_root = compute_signing_root(&deposit_message, domain);

    if !bls_verify(pubkey, signing_root.as_bytes(), signature).unwrap() {
        return;
    }
    //# Add validator and balance entries
    // bls::PublicKey::from_bytes(&pubkey.as_bytes()).unwrap()
    state
        .validators
        .push(Validator {
            pubkey: pubkey.clone(),
            withdrawal_credentials: deposit.data.withdrawal_credentials,
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            effective_balance: std::cmp::min(
                amount - (amount % T::effective_balance_increment()),
                T::max_effective_balance(),
            ),
            slashed: false,
        })
        .unwrap();
    &state.balances.push(*amount);
}

fn process_block_header<T: Config>(state: &mut BeaconState<T>, block: &BeaconBlock<T>) {
    //# Verify that the slots match
    assert!(block.slot == state.slot);
    //# Verify that the parent matches
    assert!(block.parent_root == hash_tree_root(&state.latest_block_header));
    //# Save current block as the new latest block
    state.latest_block_header = BeaconBlockHeader {
        slot: block.slot,
        parent_root: block.parent_root,
        //# `state_root` is zeroed and overwritten in the next `process_slot` call
        body_root: hash_tree_root(&block.body),
        ..BeaconBlockHeader::default()
    };
    //# Verify proposer is not slashed
    let proposer = &state.validators[get_beacon_proposer_index(&state).unwrap() as usize];
    assert!(!proposer.slashed);
}

fn process_randao<T: Config>(state: &mut BeaconState<T>, body: &BeaconBlockBody<T>) {
    let epoch = get_current_epoch(&state);
    //# Verify RANDAO reveal
    let proposer = &state.validators[get_beacon_proposer_index(&state).unwrap() as usize];
    let signing_root = compute_signing_root(&epoch, get_domain(state, T::domain_randao(), None));
    assert!(bls_verify(
        &(proposer.pubkey.clone()).try_into().unwrap(),
        signing_root.as_bytes(),
        &(body.randao_reveal.clone()).try_into().unwrap(),
    )
    .unwrap());
    //# Mix in RANDAO reveal
    let mix = xor(
        get_randao_mix(&state, epoch).unwrap().as_fixed_bytes(),
        &hash(&body.randao_reveal.as_bytes())
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let mut array = [0; 32];
    let mix = &mix[..array.len()]; // panics if not enough data
    array.copy_from_slice(mix);
    state.randao_mixes[(epoch % T::EpochsPerHistoricalVector::U64) as usize] =
        array.try_into().unwrap();
}

fn process_proposer_slashing<T: Config>(
    state: &mut BeaconState<T>,
    proposer_slashing: &ProposerSlashing,
) {
    let proposer = &state.validators[proposer_slashing.proposer_index as usize];
    // Verify slots match
    assert_eq!(
        proposer_slashing.signed_header_1.message.slot,
        proposer_slashing.signed_header_2.message.slot
    );
    // But the headers are different
    assert_ne!(
        proposer_slashing.signed_header_1,
        proposer_slashing.signed_header_2
    );
    // Check proposer is slashable
    assert!(is_slashable_validator(&proposer, get_current_epoch(state)));
    // Signatures are valid
    let signed_headers: [SignedBeaconBlockHeader; 2] = [
        proposer_slashing.signed_header_1.clone(),
        proposer_slashing.signed_header_2.clone(),
    ];
    for signed_header in &signed_headers {
        let domain = get_domain(
            state,
            T::domain_beacon_proposer() as u32,
            Some(compute_epoch_at_slot::<T>(signed_header.message.slot)),
        );
        let signing_root = compute_signing_root(&signed_header.message, domain);
        //# Sekanti eilutė tai ******* amazing. signed_root helperiuose užkomentuota
        assert!(bls_verify(
            &(proposer.pubkey.clone()).try_into().unwrap(),
            signing_root.as_bytes(),
            &(signed_header.signature.clone()).try_into().unwrap(),
        )
        .unwrap());
    }

    slash_validator(state, proposer_slashing.proposer_index, None).unwrap();
}

fn process_attester_slashing<T: Config>(
    state: &mut BeaconState<T>,
    attester_slashing: &AttesterSlashing<T>,
) {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;
    assert!(is_slashable_attestation_data(
        &attestation_1.data,
        &attestation_2.data
    ));
    assert!(validate_indexed_attestation(state, &attestation_1, true).is_ok());
    assert!(validate_indexed_attestation(state, &attestation_2, true).is_ok());

    let mut slashed_any = false;

    // Turns attesting_indices into a binary tree set. It's a set and it's ordered :)
    let attesting_indices_1 = attestation_1
        .attesting_indices
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let attesting_indices_2 = attestation_2
        .attesting_indices
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    // let mut slashable_indices = Vec::new();

    for index in &attesting_indices_1 & &attesting_indices_2 {
        let validator = &state.validators[index as usize];

        if is_slashable_validator(&validator, get_current_epoch(state)) {
            slash_validator(state, index, None).unwrap();
            slashed_any = true;
        }
    }
    assert!(slashed_any);
}

fn process_attestation<T: Config>(
    state: &mut BeaconState<T>,
    attestation: &Attestation<T>,
    verify_signature: bool,
) {
    let data = &attestation.data;
    let attestation_slot = data.slot;
    assert!(data.index < get_committee_count_at_slot(state, attestation_slot).unwrap()); //# Nėra index ir slot. ¯\_(ツ)_/¯
    assert!(
        data.target.epoch == get_previous_epoch(state)
            || data.target.epoch == get_current_epoch(state)
    );
    assert!(
        attestation_slot + T::min_attestation_inclusion_delay() <= state.slot
            && state.slot <= attestation_slot + T::SlotsPerEpoch::U64
    );

    let committee = get_beacon_committee(state, attestation_slot, data.index).unwrap();
    assert_eq!(attestation.aggregation_bits.len(), committee.len());

    let pending_attestation = PendingAttestation {
        data: attestation.data.clone(),
        aggregation_bits: attestation.aggregation_bits.clone(),
        inclusion_delay: (state.slot - attestation_slot) as u64,
        proposer_index: get_beacon_proposer_index(state).unwrap(),
    };

    if data.target.epoch == get_current_epoch(state) {
        assert_eq!(data.source, state.current_justified_checkpoint);
        state
            .current_epoch_attestations
            .push(pending_attestation)
            .unwrap();
    } else {
        assert_eq!(data.source, state.previous_justified_checkpoint);
        state
            .previous_epoch_attestations
            .push(pending_attestation)
            .unwrap();
    }

    //# Check signature
    assert!(validate_indexed_attestation(
        &state,
        &get_indexed_attestation(&state, &attestation).unwrap(),
        verify_signature,
    )
    .is_ok());
}

fn process_eth1_data<T: Config>(state: &mut BeaconState<T>, body: &BeaconBlockBody<T>) {
    state.eth1_data_votes.push(body.eth1_data.clone()).unwrap();
    let num_votes = state
        .eth1_data_votes
        .iter()
        .filter(|vote| *vote == &body.eth1_data)
        .count();

    if num_votes * 2 > T::SlotsPerEth1VotingPeriod::USIZE {
        state.eth1_data = body.eth1_data.clone();
    }
}

fn process_operations<T: Config>(state: &mut BeaconState<T>, body: &BeaconBlockBody<T>) {
    //# Verify that outstanding deposits are processed up to the maximum number of deposits
    assert_eq!(
        body.deposits.len(),
        std::cmp::min(
            T::MaxDeposits::USIZE,
            (state.eth1_data.deposit_count - state.eth1_deposit_index) as usize
        )
    );

    for proposer_slashing in body.proposer_slashings.iter() {
        process_proposer_slashing(state, proposer_slashing);
    }
    for attester_slashing in body.attester_slashings.iter() {
        process_attester_slashing(state, attester_slashing);
    }
    for attestation in body.attestations.iter() {
        process_attestation(state, attestation, true);
    }
    for deposit in body.deposits.iter() {
        process_deposit(state, deposit);
    }
    for voluntary_exit in body.voluntary_exits.iter() {
        process_voluntary_exit(state, voluntary_exit);
    }
}

#[cfg(test)]
mod scessing_tests {
    use types::{beacon_state::*, config::MainnetConfig};
    // use crate::{config::*};
    use super::*;

    #[test]
    fn process_good_block() {
        assert_eq!(2, 2);
    }
}

#[cfg(test)]
mod spec_tests {
    use std::panic::UnwindSafe;

    use spec_test_utils::{BlsSetting, Case};
    use ssz_new::SszDecode;
    use test_generator::test_resources;
    use types::{beacon_state::BeaconState, config::MinimalConfig};

    use super::*;

    // We only honor `bls_setting` in `Attestation` tests. They are the only ones that set it to 2.

    macro_rules! tests_for_operation {
        (
            $operation_name: ident,
            $processing_function: expr,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            mod $operation_name {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    run_case_specialized::<MainnetConfig>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    run_case_specialized::<MinimalConfig>(case);
                }

                fn run_case_specialized<C: Config>(case: Case) {
                    let bls_setting = case.meta().bls_setting;
                    run_case::<C, _, _>(case, stringify!($operation_name), |state, operation| {
                        $processing_function(bls_setting, state, operation)
                    });
                }
            }
        };
    }

    tests_for_operation! {
        // Test files for `block_header` are named `block.*` and contain `BeaconBlock`s.
        block,
        ignore_bls_setting(process_block_header),
        "eth2.0-spec-tests/tests/mainnet/phase0/operations/block_header/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/operations/block_header/*/*",
    }

    tests_for_operation! {
        proposer_slashing,
        ignore_bls_setting(process_proposer_slashing),
        "eth2.0-spec-tests/tests/mainnet/phase0/operations/proposer_slashing/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/operations/proposer_slashing/*/*",
    }

    tests_for_operation! {
        attester_slashing,
        ignore_bls_setting(process_attester_slashing),
        "eth2.0-spec-tests/tests/mainnet/phase0/operations/attester_slashing/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/operations/attester_slashing/*/*",
    }

    tests_for_operation! {
        attestation,
        |bls_setting, state, attestation| {
            let verify_signature = bls_setting != BlsSetting::Ignored;
            process_attestation(state, attestation, verify_signature)
        },
        "eth2.0-spec-tests/tests/mainnet/phase0/operations/attestation/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/operations/attestation/*/*",
    }

    tests_for_operation! {
        deposit,
        ignore_bls_setting(process_deposit),
        "eth2.0-spec-tests/tests/mainnet/phase0/operations/deposit/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/operations/deposit/*/*",
    }

    tests_for_operation! {
        voluntary_exit,
        ignore_bls_setting(process_voluntary_exit),
        "eth2.0-spec-tests/tests/mainnet/phase0/operations/voluntary_exit/*/*",
        "eth2.0-spec-tests/tests/minimal/phase0/operations/voluntary_exit/*/*",
    }

    fn ignore_bls_setting<T, U, V>(
        processing_function: impl FnOnce(&mut U, &V),
    ) -> impl FnOnce(T, &mut U, &V) {
        |_, state, operation| processing_function(state, operation)
    }

    fn run_case<C, D, F>(case: Case, operation_name: &str, processing_function: F)
    where
        C: Config,
        D: SszDecode,
        F: FnOnce(&mut BeaconState<C>, &D) + UnwindSafe,
    {
        let process_operation = || {
            let mut state = case.ssz("pre");
            let operation = case.ssz(operation_name);
            processing_function(&mut state, &operation);
            state
        };
        match case.try_ssz("post") {
            Some(expected_post) => assert_eq!(process_operation(), expected_post),
            // The state transition code as it is now panics on error instead of returning `Result`.
            // We have to use `std::panic::catch_unwind` to verify that state transitions fail.
            // This may result in tests falsely succeeding.
            None => assert!(std::panic::catch_unwind(process_operation).is_err()),
        }
    }
}
