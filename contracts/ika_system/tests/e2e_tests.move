// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#[allow(unused_mut_ref)]
module ika_system::e2e_tests;

use std::unit_test::assert_eq;
use ika_system::{e2e_runner, test_utils};

const HUNDRED_PERCENT_COMMISSION_RATE: u16 = 100_00; // 100.00% commission in bps

const EPOCH_DURATION_MS: u64 = 24 * 60 * 60 * 1000; // 1 day
const MID_CONFIGURATION_DELTA_MS: u64 = 24 * 60 * 60 * 1000 / 2; // 1 day / 2


#[test]
fun test_init_and_first_epoch_change() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    assert!(runner.next_epoch_active_committee().is_none());

    // === perform another epoch change ===
    // === start with mid epoch reconfiguration to get ready for advancing epoch ==

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    assert_eq!(runner.epoch(), 1);
    let bls_committee = runner.active_committee();
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));

    assert!(runner.next_epoch_active_committee().is_some());

    // === advance clock and change epoch ===
    // === check if epoch was changed as expected ===

    runner.perform_advance_epoch(
        option::none()
    );

    assert_eq!(runner.epoch(), 2);
    let bls_committee = runner.active_committee();
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));

    // === cleanup ===

    validators.destroy!(|validator| validator.destroy());
    runner.destroy();
}

#[test]
fun test_stake_after_committee_selection() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    let mut excluded_validator = validators.pop_back();

    // stake with each validator except one
    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    let admin = runner.admin();

    // === perform another epoch change ===
    // === start with mid epoch reconfiguration to get ready for advancing epoch ==

    runner.increment_timestamp_ms(MID_CONFIGURATION_DELTA_MS);
    runner.tx!(admin, |system, dwallet_2pc_mpc_coordinator, clock, ctx| {
        system.request_reconfig_mid_epoch(dwallet_2pc_mpc_coordinator, clock, ctx);
    });

    // === add stake to excluded validator ===

    runner.tx!(excluded_validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, ctx| {
        let (cap, operation_cap, commission_cap) = system.request_add_validator_candidate(
            excluded_validator.name(),
            excluded_validator.protocol_pubkey_bytes(),
            excluded_validator.network_pubkey_bytes(),
            excluded_validator.consensus_pubkey_bytes(),
            excluded_validator.mpc_data(ctx),
            excluded_validator.create_proof_of_possession(),
            excluded_validator.network_address(),
            excluded_validator.p2p_address(),
            excluded_validator.consensus_address(),
            excluded_validator.commission_rate(),
            excluded_validator.metadata(),
            ctx,
        );
        excluded_validator.set_validator_cap(cap);
        excluded_validator.set_validator_operation_cap(operation_cap);
        excluded_validator.set_validator_commission_cap(commission_cap);
        let coin = test_utils::mint_inku(excluded_validator.stake_amount(), ctx);
        let staked_ika = system.request_add_stake(coin, excluded_validator.validator_id(), ctx);
        excluded_validator.staked_ika().push_back(staked_ika);
        system.request_add_validator(excluded_validator.cap());
    });

    // === complete reconfiguration ===

    runner.perform_network_encryption_key_reconfiguration(&mut validators);

    runner.perform_default_pricing_calculation_votes();

    // === advance clock and change epoch ===
    // === check if epoch was changed as expected ===

    runner.perform_advance_epoch(
        option::none()
    );

    // === initiate epoch change ===
    // === check if epoch state is changed correctly ==

    assert_eq!(runner.epoch(), 2);
    let bls_committee = runner.active_committee();
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));
    // excluded validator is not in the committee
    assert!(!bls_committee.contains(&excluded_validator.validator_id()));

    // === perform another mid epoch reconfiguration ===

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    // === advance epoch ===

    runner.perform_advance_epoch(
        option::none()
    );

    // === check if previously excluded validator is now also in the committee ===

    assert_eq!(runner.epoch(), 3);
    let bls_committee = runner.active_committee();
    // add excluded validator back to the list
    validators.push_back(excluded_validator);

    // excluded validator should now be in the committee
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));

    // let's check now if the new committee works as expected

    // === perform mid epoch reconfiguration ===

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    // === advance epoch ===

    runner.perform_advance_epoch(
        option::none()
    );

    assert_eq!(runner.epoch(), 4);
    let bls_committee = runner.active_committee();
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));

    // all validators initially staked with are in the committee
    // previously excluded validator is now also in the committee

    // === cleanup ===

    validators.destroy!(|validator| validator.destroy());
    runner.destroy();
}

#[test]
fun validator_voting_parameters() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    // 10 validators, we'll set consensus_validation_ika, computation_ika, gas_fee_reimbursement_sui and gas_fee_reimbursement_sui_for_system_calls
    // to 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000 for all protocols.
    let mut i = 1;
    validators.do_mut!(|validator| {
        runner.tx!(validator.sui_address(), |system, dwallet_2pc_mpc_coordinator, _clock, _ctx| {
            let pricing = test_utils::create_pricing_for_default_protocols(i * 1000);
            system.set_pricing_vote(dwallet_2pc_mpc_coordinator, pricing, validator.operation_cap());

            i = i + 1;
        });
    });

    assert_eq!(runner.epoch(), 1);

    // === perform mid epoch reconfiguration ===

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    // === advance epoch ===

    runner.perform_advance_epoch(
        option::none()
    );

    assert_eq!(runner.epoch(), 2);

    e2e_runner::assert_pricing_values_for_default_protocols(&mut runner, 7000);

    validators.destroy!(|validator| validator.destroy());
    runner.destroy();
}

#[test, expected_failure(abort_code = ika_system::system_inner::EHaveNotReachedMidEpochTime)]
fun test_mid_epoch_reconfiguration_too_soon_fail() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    // One millisecond before mid epoch reconfiguration can be performed
    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::some(MID_CONFIGURATION_DELTA_MS - 1)
    );

    abort 0
}

#[test, expected_failure(abort_code = ika_system::system_inner::EHaveNotReachedEndEpochTime)]
fun test_advance_epoch_too_soon_fail() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );


    // One millisecond before advance epoch can be performed
    runner.perform_advance_epoch(
        option::some(EPOCH_DURATION_MS - MID_CONFIGURATION_DELTA_MS - 1)
    );

    abort 0
}

#[test]
fun test_epoch_change_with_rewards_and_commission() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    validators.do_mut!(|validator| validator.set_commission_rate(HUNDRED_PERCENT_COMMISSION_RATE));

    let pricing = test_utils::create_pricing_for_default_protocols(5000);

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::some(pricing),
        option::none(),
    );

    let admin = runner.admin();

    // === perform dkg first round to add rewards ===

    runner.perform_dwallet_dkg_first_round(&mut validators, admin);

    // === perform mid epoch reconfiguration ===

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    // === advance epoch ===

    runner.perform_advance_epoch(
        option::none()
    );

    assert_eq!(runner.epoch(), 2);


    // === check rewards for each validator ===
    // stake subsidy is 10% of the total supply: 10,000,000,000 (IKA) * 1,000,000,000 (INKU/IKA) * 10% = 1,000,000,000,000,000,000 INKU
    // 1,000,000,000,000,000,000 INKU / 365 days = 2,739,726,027,397,260 INKU per day (epoch)
    // 2,739,726,027,397,260 INKU / 10 validators = 27,3972,602,739,726 INKU per validator per day (epoch)
    // From payment we get 5,000 INKU (consensus validation) + 5,000 INKU (computation) = 10,000 INKU total
    // 10,000 INKU / 10 validators = 1,000 INKU per validator
    // each validator is getting 27,3972,602,739,726 INKU from stake subsidy and 1,000 INKU from payment in rewards
    // in total 27,3972,602,740,726 INKU for each validator
    validators.do_mut!(|validator| {
        runner.tx!(validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, ctx| {
            let commission = system.collect_commission(validator.commission_cap(), option::none(), ctx);

            assert_eq!(commission.burn_for_testing(), 273_972_602_739_726 + 1_000);
        });
    });

    // === cleanup ===

    validators.destroy!(|validator| validator.destroy());
    runner.destroy();
}

#[test]
fun test_update_validator_metadata() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    let validator = &mut validators[0];

    runner.tx!(validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, _ctx| {
        let mut metadata = system.validator_metadata(validator.validator_id());
        metadata.set_description(b"Ika Chan".to_string());
        metadata.set_project_url(b"https://chan.ika.xyz/".to_string());
        system.set_validator_metadata(metadata, validator.operation_cap());
    });

    runner.tx!(validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, _ctx| {
        let metadata = system.validator_metadata(validator.validator_id());
        assert_eq!(metadata.description(), b"Ika Chan".to_string());
        assert_eq!(metadata.project_url(), b"https://chan.ika.xyz/".to_string());
    });

    validators.destroy!(|validator| validator.destroy());
    runner.destroy();
}

#[test, expected_failure(abort_code = ika_system::validator_info::EInvalidProofOfPossession)]
fun test_register_invalid_pop_signer() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();
    // wrong signer
    let pop = validators[1].create_proof_of_possession();
    let validator = &mut validators[0];
    // Test fails here
    runner.tx_for_initialization!(validator.sui_address(), |system, _clock, ctx| {
        let (cap, operation_cap, commission_cap) = system.request_add_validator_candidate(
            validator.name(),
            validator.protocol_pubkey_bytes(),
            validator.network_pubkey_bytes(),
            validator.consensus_pubkey_bytes(),
            validator.mpc_data(ctx),
            pop,
            validator.network_address(),
            validator.p2p_address(),
            validator.consensus_address(),
            validator.commission_rate(),
            validator.metadata(),
            ctx,
        );
        validator.set_validator_cap(cap);
        validator.set_validator_operation_cap(operation_cap);
        validator.set_validator_commission_cap(commission_cap);
    });

    abort 0
}

#[test]
fun withdraw_rewards_before_joining_committee() {
    let (mut runner, mut validators) = e2e_runner::setup_default_test_runner_and_validators();

    let mut excluded_validator = validators.pop_back();

    e2e_runner::initialize_committee_for_epoch_one(
        &mut runner,
        &mut validators,
        option::none(),
        option::none(),
        option::none(),
        option::none(),
    );

    runner.tx!(excluded_validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, ctx| {
        let (cap, operation_cap, commission_cap) = system.request_add_validator_candidate(
            excluded_validator.name(),
            excluded_validator.protocol_pubkey_bytes(),
            excluded_validator.network_pubkey_bytes(),
            excluded_validator.consensus_pubkey_bytes(),
            excluded_validator.mpc_data(ctx),
            excluded_validator.create_proof_of_possession(),
            excluded_validator.network_address(),
            excluded_validator.p2p_address(),
            excluded_validator.consensus_address(),
            excluded_validator.commission_rate(),
            excluded_validator.metadata(),
            ctx,
        );
        excluded_validator.set_validator_cap(cap);
        excluded_validator.set_validator_operation_cap(operation_cap);
        excluded_validator.set_validator_commission_cap(commission_cap);
        let coin = test_utils::mint_inku(1_000_000_000, ctx);
        let staked_ika = system.request_add_stake(coin, excluded_validator.validator_id(), ctx);
        excluded_validator.staked_ika().push_back(staked_ika);
    });

    // === perform mid epoch reconfiguration ===

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    // === advance epoch ===

    runner.perform_advance_epoch(
        option::none()
    );

    assert_eq!(runner.epoch(), 2);
    let bls_committee = runner.active_committee();
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));

    runner.tx!(excluded_validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, ctx| {
        let coin = system.withdraw_stake(excluded_validator.staked_ika().pop_back(), ctx);
        coin.burn_for_testing();
    });

    // === add stake to excluded validator again ===

    runner.tx!(excluded_validator.sui_address(), |system, _dwallet_2pc_mpc_coordinator, _clock, ctx| {
        let coin = test_utils::mint_inku(excluded_validator.stake_amount(), ctx);
        let staked_ika = system.request_add_stake(coin, excluded_validator.validator_id(), ctx);
        excluded_validator.staked_ika().push_back(staked_ika);
        system.request_add_validator(excluded_validator.cap());
    });

    // === perform mid epoch reconfiguration ===

    runner.perform_mid_epoch_reconfiguration(
        &mut validators,
        option::none()
    );

    // === advance epoch ===

    runner.perform_advance_epoch(
        option::none()
    );

    validators.push_back(excluded_validator);

    assert_eq!(runner.epoch(), 3);
    let bls_committee = runner.active_committee();
    assert_eq!(bls_committee.members().length(), validators.length());
    validators.do_ref!(|validator| assert!(bls_committee.contains(&validator.validator_id())));

    // === cleanup ===

    validators.destroy!(|validator| validator.destroy());
    runner.destroy();
}
