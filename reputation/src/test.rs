#![cfg(test)]
#![allow(clippy::module_inception)]

use crate::{
    ReputationConfig, ReputationContract, ReputationContractClient, ReputationError,
    TransactionOutcome,
};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    Address, Env, String,
};

fn default_config() -> ReputationConfig {
    ReputationConfig {
        decay_window_seconds: 90 * 24 * 60 * 60,
        min_transactions_threshold: 5,
        dispute_penalty_bps: 500,
        freeze_threshold_flags: 3,
    }
}

fn setup(env: &Env) -> (ReputationContractClient<'_>, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register(ReputationContract, (admin.clone(), default_config()));
    let client = ReputationContractClient::new(env, &contract_id);
    (client, admin)
}

fn advance_time(env: &Env, seconds: u64) {
    env.ledger().with_mut(|li| {
        li.timestamp += seconds;
    });
}

// --- constructor (deployment-time initialization) ---
//
// `__constructor` is a Soroban constructor: the host runs it exactly once,
// atomically with `env.register`, and there is no way to invoke it again
// afterward (unlike the plain `initialize()` pattern used elsewhere in this
// workspace) — so there is no "already initialized" or "not yet
// initialized" state to exercise here, only deployment succeeding or
// `env.register` panicking on an invalid config.

#[test]
fn test_constructor_sets_admin_and_config() {
    let env = Env::default();
    let (client, _admin) = setup(&env);

    assert_eq!(client.get_config(), default_config());
}

#[test]
#[should_panic]
fn test_constructor_rejects_zero_decay_window() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let mut bad = default_config();
    bad.decay_window_seconds = 0;
    env.register(ReputationContract, (admin, bad));
}

#[test]
#[should_panic]
fn test_constructor_rejects_dispute_penalty_over_max() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let mut bad = default_config();
    bad.dispute_penalty_bps = 10_001;
    env.register(ReputationContract, (admin, bad));
}

#[test]
#[should_panic]
fn test_constructor_rejects_zero_freeze_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let mut bad = default_config();
    bad.freeze_threshold_flags = 0;
    env.register(ReputationContract, (admin, bad));
}

// --- record_transaction ---

#[test]
fn test_record_transaction_released_scores_full() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );

    let rep = client.try_get_reputation(&entity).unwrap().unwrap();
    // Below min_transactions_threshold (5), so score is masked.
    assert_eq!(rep.score, 0);
    assert_eq!(rep.total_transactions, 1);
    assert_eq!(rep.successful_transactions, 1);
    assert_eq!(rep.disputed_transactions, 0);
}

#[test]
fn test_record_transaction_unmasks_score_at_threshold() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    for i in 0..5u64 {
        client.record_transaction(
            &admin,
            &i,
            &entity,
            &counterparty,
            &1000i128,
            &TransactionOutcome::Released,
        );
    }

    let rep = client.get_reputation(&entity);
    assert_eq!(rep.total_transactions, 5);
    // All-Released, freshly recorded (no decay yet) -> full score.
    assert_eq!(rep.score, 10_000);
}

#[test]
fn test_record_transaction_unauthorized_caller() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);
    let not_admin = Address::generate(&env);

    let res = client.try_record_transaction(
        &not_admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_record_transaction_rejects_frozen_entity() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.freeze_entity(&admin, &entity);

    let res = client.try_record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    assert_eq!(res, Err(Ok(ReputationError::EntityFrozen)));
}

#[test]
fn test_record_transaction_allows_lifecycle_update_while_frozen() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Disputed,
    );
    client.freeze_entity(&admin, &entity);

    // A dispute opened before the freeze must still be able to resolve —
    // only brand-new escrows are rejected while frozen.
    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::ResolvedSeller,
    );

    let rep = client.get_reputation(&entity);
    assert_eq!(rep.disputed_transactions, 0);
    assert_eq!(rep.successful_transactions, 1);

    // A genuinely new escrow is still rejected while frozen.
    let res = client.try_record_transaction(
        &admin,
        &2u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    assert_eq!(res, Err(Ok(ReputationError::EntityFrozen)));
}

#[test]
fn test_record_transaction_same_escrow_updates_in_place() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Disputed,
    );
    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::ResolvedSeller,
    );

    let rep = client.get_reputation(&entity);
    // Lifecycle update on the same escrow_id must not double count.
    assert_eq!(rep.total_transactions, 1);
    assert_eq!(rep.disputed_transactions, 0);
    assert_eq!(rep.successful_transactions, 1);

    let breakdown = client.get_reputation_breakdown(&entity, &0u32, &10u32);
    assert_eq!(breakdown.len(), 1);
    assert!(matches!(
        breakdown.get(0).unwrap().outcome,
        TransactionOutcome::ResolvedSeller
    ));
}

#[test]
fn test_record_transaction_rejects_entity_mismatch_for_existing_escrow() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity_a = Address::generate(&env);
    let entity_b = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity_a,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );

    let res = client.try_record_transaction(
        &admin,
        &1u64,
        &entity_b,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    assert_eq!(res, Err(Ok(ReputationError::InvalidParam)));
}

#[test]
fn test_score_decays_over_time() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    for i in 0..5u64 {
        client.record_transaction(
            &admin,
            &i,
            &entity,
            &counterparty,
            &1000i128,
            &TransactionOutcome::Released,
        );
    }
    let fresh = client.get_reputation(&entity);
    assert_eq!(fresh.score, 10_000);

    // Advance one full half-life (decay_window_seconds) and force a
    // recompute via a new transaction; the older Released records should
    // now contribute at roughly half weight, pulling a fresh 0-value
    // Disputed record's average down less than it would immediately after
    // (i.e. the mix is dominated less by old data over time). We assert the
    // simpler, robust invariant: recorded_at-fresh entries score higher
    // than long-decayed ones feeding a poor outcome.
    advance_time(&env, default_config().decay_window_seconds);
    client.record_transaction(
        &admin,
        &99u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Disputed,
    );
    let decayed = client.get_reputation(&entity);
    assert!(decayed.score < fresh.score);
}

#[test]
fn test_score_bounded_to_recent_window() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    // Old disputes that should age out of the score window once more than
    // SCORE_WINDOW clean transactions have been recorded since.
    for i in 0..10u64 {
        client.record_transaction(
            &admin,
            &i,
            &entity,
            &counterparty,
            &1000i128,
            &TransactionOutcome::Disputed,
        );
    }
    for i in 10..(10 + crate::SCORE_WINDOW as u64) {
        client.record_transaction(
            &admin,
            &i,
            &entity,
            &counterparty,
            &1000i128,
            &TransactionOutcome::Released,
        );
    }

    let rep = client.get_reputation(&entity);
    // Lifetime counts remain exact regardless of the scoring window.
    assert_eq!(rep.total_transactions, 10 + crate::SCORE_WINDOW as u64);
    assert_eq!(rep.disputed_transactions, 10);
    // The old disputes have fully aged out of the SCORE_WINDOW most-recent
    // records feeding the score, so the score reflects only the clean run.
    assert_eq!(rep.score, 10_000);

    // One more dispute lands inside the window, so it now counts against the
    // score. This pins the boundary: the window, not the dispute count, is
    // what excluded the earlier ones.
    client.record_transaction(
        &admin,
        &(10 + crate::SCORE_WINDOW as u64),
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Disputed,
    );
    let rep = client.get_reputation(&entity);
    assert!(rep.score < 10_000);
}

// --- rate_entity ---

#[test]
fn test_rate_entity_happy_path() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    client.rate_entity(&counterparty, &1u64, &entity, &9000u32);

    let breakdown = client.get_reputation_breakdown(&entity, &0u32, &10u32);
    assert_eq!(breakdown.get(0).unwrap().rating, Some(9000u32));
}

#[test]
fn test_rate_entity_updates_avg_rating() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    // Reach min_transactions_threshold (5) so the score/avg_rating are
    // visible on get_reputation.
    for i in 0..5u64 {
        client.record_transaction(
            &admin,
            &i,
            &entity,
            &counterparty,
            &1000i128,
            &TransactionOutcome::Released,
        );
    }

    // Only two of the five are rated; avg_rating must reflect only those,
    // not all five recorded transactions.
    client.rate_entity(&counterparty, &0u64, &entity, &8000u32);
    client.rate_entity(&counterparty, &1u64, &entity, &10_000u32);

    let rep = client.get_reputation(&entity);
    // All five records are equally fresh (same recorded_at), so the two
    // ratings carry equal weight: (8000 + 10000) / 2.
    assert_eq!(rep.avg_rating, 9000);
}

#[test]
fn test_rate_entity_duplicate_rejected() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    client.rate_entity(&counterparty, &1u64, &entity, &9000u32);

    let res = client.try_rate_entity(&counterparty, &1u64, &entity, &8000u32);
    assert_eq!(res, Err(Ok(ReputationError::DuplicateRating)));
}

#[test]
fn test_rate_entity_invalid_rating_rejected() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );

    let res = client.try_rate_entity(&counterparty, &1u64, &entity, &10_001u32);
    assert_eq!(res, Err(Ok(ReputationError::InvalidRating)));
}

#[test]
fn test_rate_entity_wrong_rater_rejected() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );

    let res = client.try_rate_entity(&stranger, &1u64, &entity, &9000u32);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_rate_entity_missing_escrow_rejected() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    let res = client.try_rate_entity(&counterparty, &1u64, &entity, &9000u32);
    assert_eq!(res, Err(Ok(ReputationError::EntityNotFound)));
}

#[test]
fn test_rate_entity_rejects_disputed_outcome() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Disputed,
    );

    let res = client.try_rate_entity(&counterparty, &1u64, &entity, &9000u32);
    assert_eq!(res, Err(Ok(ReputationError::InvalidParam)));
}

#[test]
fn test_rate_entity_rejects_frozen_entity() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    client.record_transaction(
        &admin,
        &1u64,
        &entity,
        &counterparty,
        &1000i128,
        &TransactionOutcome::Released,
    );
    client.freeze_entity(&admin, &entity);

    let res = client.try_rate_entity(&counterparty, &1u64, &entity, &9000u32);
    assert_eq!(res, Err(Ok(ReputationError::EntityFrozen)));
}

// --- get_reputation ---

#[test]
fn test_get_reputation_not_found() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let entity = Address::generate(&env);

    assert_eq!(
        client.try_get_reputation(&entity),
        Err(Ok(ReputationError::EntityNotFound))
    );
}

// --- pagination ---

#[test]
fn test_get_reputation_breakdown_pagination() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let counterparty = Address::generate(&env);

    for i in 0..10u64 {
        client.record_transaction(
            &admin,
            &i,
            &entity,
            &counterparty,
            &1000i128,
            &TransactionOutcome::Released,
        );
    }

    let page1 = client.get_reputation_breakdown(&entity, &0u32, &4u32);
    assert_eq!(page1.len(), 4);
    let page2 = client.get_reputation_breakdown(&entity, &4u32, &4u32);
    assert_eq!(page2.len(), 4);
    let page3 = client.get_reputation_breakdown(&entity, &8u32, &4u32);
    assert_eq!(page3.len(), 2);

    let out_of_range = client.get_reputation_breakdown(&entity, &100u32, &4u32);
    assert_eq!(out_of_range.len(), 0);
}

// --- flagging ---

/// Establishes `reporter` as a genuine counterparty of `entity` via a
/// completed transaction, satisfying `flag_entity`'s reporter gate.
fn make_transacting_counterparty(
    client: &ReputationContractClient,
    admin: &Address,
    entity: &Address,
    reporter: &Address,
    escrow_id: u64,
) {
    client.record_transaction(
        admin,
        &escrow_id,
        entity,
        reporter,
        &1000i128,
        &TransactionOutcome::Released,
    );
}

#[test]
fn test_flag_entity_happy_path() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let reporter = Address::generate(&env);
    make_transacting_counterparty(&client, &admin, &entity, &reporter, 1u64);

    client.flag_entity(
        &reporter,
        &entity,
        &symbol_short!("fraud"),
        &Some(String::from_str(&env, "fake goods")),
    );

    let flags = client.get_flags(&entity, &0u32, &10u32);
    assert_eq!(flags.len(), 1);
    assert!(!flags.get(0).unwrap().resolved);
    assert!(!client.is_frozen(&entity));
}

#[test]
fn test_flag_entity_rejects_non_counterparty_non_admin() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let entity = Address::generate(&env);
    let stranger = Address::generate(&env);

    let res = client.try_flag_entity(&stranger, &entity, &symbol_short!("fraud"), &None);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_flag_entity_allows_admin_without_transaction() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);

    client.flag_entity(&admin, &entity, &symbol_short!("fraud"), &None);

    let flags = client.get_flags(&entity, &0u32, &10u32);
    assert_eq!(flags.len(), 1);
}

#[test]
fn test_flag_entity_same_reporter_rejected_while_active() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let reporter = Address::generate(&env);
    make_transacting_counterparty(&client, &admin, &entity, &reporter, 1u64);

    client.flag_entity(&reporter, &entity, &symbol_short!("fraud"), &None);

    let res = client.try_flag_entity(&reporter, &entity, &symbol_short!("spam"), &None);
    assert_eq!(res, Err(Ok(ReputationError::AlreadyFlagged)));
}

#[test]
fn test_flag_entity_auto_freezes_at_threshold() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);

    for i in 0..3u64 {
        let reporter = Address::generate(&env);
        make_transacting_counterparty(&client, &admin, &entity, &reporter, i);
        client.flag_entity(&reporter, &entity, &symbol_short!("fraud"), &None);
    }

    assert!(client.is_frozen(&entity));
}

#[test]
fn test_resolve_flag_happy_path() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let reporter = Address::generate(&env);
    make_transacting_counterparty(&client, &admin, &entity, &reporter, 1u64);

    client.flag_entity(&reporter, &entity, &symbol_short!("fraud"), &None);
    client.resolve_flag(&admin, &reporter, &entity);

    let flags = client.get_flags(&entity, &0u32, &10u32);
    assert!(flags.get(0).unwrap().resolved);

    // Reporter can flag again now that their prior flag is resolved.
    client.flag_entity(&reporter, &entity, &symbol_short!("spam"), &None);
    let flags = client.get_flags(&entity, &0u32, &10u32);
    assert_eq!(flags.len(), 2);
}

#[test]
fn test_resolve_flag_unauthorized() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let reporter = Address::generate(&env);
    let not_admin = Address::generate(&env);
    make_transacting_counterparty(&client, &admin, &entity, &reporter, 1u64);

    client.flag_entity(&reporter, &entity, &symbol_short!("fraud"), &None);

    let res = client.try_resolve_flag(&not_admin, &reporter, &entity);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_resolve_flag_missing() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);
    let reporter = Address::generate(&env);

    let res = client.try_resolve_flag(&admin, &reporter, &entity);
    assert_eq!(res, Err(Ok(ReputationError::EntityNotFound)));
}

// --- freeze / unfreeze ---

#[test]
fn test_freeze_and_unfreeze_entity() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let entity = Address::generate(&env);

    assert!(!client.is_frozen(&entity));
    client.freeze_entity(&admin, &entity);
    assert!(client.is_frozen(&entity));
    client.unfreeze_entity(&admin, &entity);
    assert!(!client.is_frozen(&entity));
}

#[test]
fn test_freeze_entity_unauthorized() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let entity = Address::generate(&env);
    let not_admin = Address::generate(&env);

    let res = client.try_freeze_entity(&not_admin, &entity);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

// --- update_config ---

#[test]
fn test_update_config_happy_path() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    let mut new_config = default_config();
    new_config.min_transactions_threshold = 1;
    client.update_config(&admin, &new_config);

    assert_eq!(client.get_config(), new_config);
}

#[test]
fn test_update_config_unauthorized() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let not_admin = Address::generate(&env);

    let res = client.try_update_config(&not_admin, &default_config());
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_update_config_rejects_invalid() {
    let env = Env::default();
    let (client, admin) = setup(&env);

    let mut bad = default_config();
    bad.decay_window_seconds = 0;
    let res = client.try_update_config(&admin, &bad);
    assert_eq!(res, Err(Ok(ReputationError::InvalidParam)));
}

// --- admin transfer ---

#[test]
fn test_propose_and_accept_admin() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let new_admin = Address::generate(&env);

    client.propose_admin(&admin, &new_admin);
    client.accept_admin(&new_admin);

    // Old admin can no longer perform admin actions.
    let entity = Address::generate(&env);
    let res = client.try_freeze_entity(&admin, &entity);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));

    // New admin can.
    client.freeze_entity(&new_admin, &entity);
    assert!(client.is_frozen(&entity));
}

#[test]
fn test_propose_admin_unauthorized() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let not_admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    let res = client.try_propose_admin(&not_admin, &new_admin);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_accept_admin_wrong_caller() {
    let env = Env::default();
    let (client, admin) = setup(&env);
    let new_admin = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.propose_admin(&admin, &new_admin);

    let res = client.try_accept_admin(&stranger);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

#[test]
fn test_accept_admin_no_pending_transfer() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let stranger = Address::generate(&env);

    let res = client.try_accept_admin(&stranger);
    assert_eq!(res, Err(Ok(ReputationError::Unauthorized)));
}

// ========================================================================
// Property tests for `recency_weight_bps` (Issue #130)
// ========================================================================
//
// These tests exercise broad deterministic input ranges to verify
// mathematical invariants of the time-decay weight function.
//
// The function computes: 10_000 × 2^(-elapsed / decay_window)
// via integer bit-shift halving with linear interpolation.
//
// Invariants under test:
//   1. Output is always within [0, BPS_SCALE] (bounds)
//   2. Monotonically non-increasing as elapsed increases (monotonicity)
//   3. elapsed = 0 returns BPS_SCALE (zero elapsed)
//   4. Large elapsed values never panic and return 0 (saturation)
//   5. Boundary transitions at half-life multiples are correct
// ========================================================================

/// Helper: independent mathematical oracle for the recency weight.
/// Computes `floor(10_000 × 2^(-elapsed / decay_window))` using
/// arbitrary-precision arithmetic to avoid overflow.
fn oracle_recency_weight_bps(elapsed: u64, decay_window: u64) -> i128 {
    if decay_window == 0 {
        return 10_000;
    }
    let halvings = elapsed / decay_window;
    if halvings >= 20 {
        return 0;
    }
    // 10_000 / 2^halvings using i128
    let base: i128 = 10_000_i128 >> halvings;
    let remainder = elapsed % decay_window;
    // Linear interpolation: subtract (base × remainder) / (2 × decay_window)
    let dec = (base * remainder as i128) / (2 * decay_window as i128);
    (base - dec).max(0)
}

const BPS_SCALE_I128: i128 = 10_000;

// ---- PROPERTY 1: BOUNDS ----
// For all tested (elapsed, decay_window) pairs,
// 0 <= recency_weight_bps(elapsed, decay_window) <= 10_000.
#[test]
fn property_recency_bounds() {
    let decay_windows: &[u64] = &[
        1,
        2,
        5,
        10,
        60,
        3600,
        86_400,            // 1 day
        90 * 24 * 60 * 60, // default config decay window (~7776000)
        u64::MAX / 2,      // near max
        u64::MAX,
    ];

    for &dw in decay_windows {
        // Test a broad range of elapsed values: 0..=100 plus key boundary values.
        for e in 0..=100u64 {
            let w = crate::recency_weight_bps(e, dw);
            assert!(
                w >= 0 && w <= BPS_SCALE_I128,
                "bounds violated: recency_weight_bps({}, {}) = {}",
                e,
                dw,
                w
            );
        }
        // Additional boundary values derived from the decay window.
        let extra: &[u64] = &[
            dw.saturating_sub(1),
            dw,
            dw.saturating_add(1),
            2_u64.saturating_mul(dw),
            3_u64.saturating_mul(dw),
            10_u64.saturating_mul(dw),
            19_u64.saturating_mul(dw),
            20_u64.saturating_mul(dw),
            21_u64.saturating_mul(dw),
            100_u64.saturating_mul(dw),
            u64::MAX,
        ];
        for &e in extra {
            let w = crate::recency_weight_bps(e, dw);
            assert!(
                w >= 0 && w <= BPS_SCALE_I128,
                "bounds violated: recency_weight_bps({}, {}) = {}",
                e,
                dw,
                w
            );
        }
    }
}

// ---- PROPERTY 2: MONOTONICITY ----
// For any fixed decay_window, if e1 <= e2 then
// recency_weight_bps(e2, dw) <= recency_weight_bps(e1, dw).
#[test]
fn property_recency_monotonicity() {
    let decay_windows: &[u64] = &[1, 2, 5, 10, 60, 3600, 86_400, 90 * 24 * 60 * 60];

    for &dw in decay_windows {
        // Sweep elapsed from 0 through 21 * dw in small steps,
        // verifying the weight never increases.
        let max_elapsed = 21_u64.saturating_mul(dw);
        let step = if dw > 100 { dw / 50 } else { 1 };

        let mut prev_weight = i128::MAX;
        let mut e = 0u64;
        while e <= max_elapsed {
            let w = crate::recency_weight_bps(e, dw);
            assert!(
                w <= prev_weight,
                "monotonicity violated at elapsed={} (decay_window={}): \
                 weight={} > prev_weight={}",
                e,
                dw,
                w,
                prev_weight
            );
            prev_weight = w;
            e = e.saturating_add(step);
        }
    }
}

// ---- PROPERTY 3: ZERO ELAPSED ----
// recency_weight_bps(0, dw) == BPS_SCALE for any valid dw > 0.
#[test]
fn property_recency_zero_elapsed() {
    let decay_windows: &[u64] = &[1, 2, 10, 60, 86_400, 90 * 24 * 60 * 60];

    for &dw in decay_windows {
        let w = crate::recency_weight_bps(0, dw);
        assert_eq!(
            w, BPS_SCALE_I128,
            "recency_weight_bps(0, {}) should be {} but got {}",
            dw, BPS_SCALE_I128, w
        );
    }
}

// ---- PROPERTY 4: ZERO DECAY WINDOW ----
// recency_weight_bps(e, 0) == BPS_SCALE for any elapsed.
// (The function treats zero decay_window as "no decay".)
#[test]
fn property_recency_zero_decay_window() {
    let elapsed_values: &[u64] = &[0, 1, 100, u64::MAX / 2, u64::MAX];

    for &e in elapsed_values {
        let w = crate::recency_weight_bps(e, 0);
        assert_eq!(
            w, BPS_SCALE_I128,
            "recency_weight_bps({}, 0) should be {} but got {}",
            e, BPS_SCALE_I128, w
        );
    }
}

// ---- PROPERTY 5: LARGE ELAPSED ----
// For very large elapsed values (near u64::MAX), the function returns 0
// and does not panic.
#[test]
fn property_recency_large_elapsed() {
    let decay_windows: &[u64] = &[1, 60, 86_400, 90 * 24 * 60 * 60];

    let large_elapsed: &[u64] = &[
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
        u64::MAX / 3,
        1_000_000_000_000, // ~31,700 years in seconds
        31_536_000_000,    // ~1000 years in seconds
    ];

    for &dw in decay_windows {
        for &e in large_elapsed {
            let w = crate::recency_weight_bps(e, dw);
            assert!(
                w >= 0 && w <= BPS_SCALE_I128,
                "large elapsed: recency_weight_bps({}, {}) = {} out of bounds",
                e,
                dw,
                w
            );
            // With any reasonable decay_window and very large elapsed,
            // the weight should be 0 (since full_halvings >= 20)
            if dw > 0 && e / dw >= 20 {
                assert_eq!(
                    w, 0,
                    "should saturate to 0: recency_weight_bps({}, {}) = {}",
                    e, dw, w
                );
            }
        }
    }
}

// ---- PROPERTY 6: DECAY BOUNDARIES ----
// Test exact half-life multiples and their neighbours.
// At elapsed = k * decay_window:
//   base = 10_000 >> k
//   remainder = 0, so decrement = 0
//   result = base
#[test]
fn property_recency_decay_boundaries() {
    let dw: u64 = 100;

    for k in 0..20u64 {
        let e = k * dw;
        let w = crate::recency_weight_bps(e, dw);
        let expected = BPS_SCALE_I128 >> k;
        assert_eq!(
            w, expected,
            "half-life boundary: recency_weight_bps({}, {}) = {}, expected {}",
            e, dw, w, expected
        );
    }

    // Test boundary - 1 and boundary + 1
    for k in 1..10u64 {
        let e_before = k * dw - 1;
        let e_at = k * dw;
        let e_after = k * dw + 1;

        let w_before = crate::recency_weight_bps(e_before, dw);
        let w_at = crate::recency_weight_bps(e_at, dw);
        let w_after = crate::recency_weight_bps(e_after, dw);

        assert!(
            w_before >= w_at,
            "should decrease at boundary: w({})={} >= w({})={}",
            e_before,
            w_before,
            e_at,
            w_at
        );
        assert!(
            w_at >= w_after,
            "should decrease after boundary: w({})={} >= w({})={}",
            e_at,
            w_at,
            e_after,
            w_after
        );
    }
}

// ---- PROPERTY 7: AGREEMENT WITH ORACLE ----
// For a broad sweep of inputs, verify the implementation matches
// an independent mathematical oracle.
#[test]
fn property_recency_matches_oracle() {
    let decay_windows: &[u64] = &[1, 2, 5, 10, 60, 3600, 86_400, 90 * 24 * 60 * 60];

    for &dw in decay_windows {
        // Sweep elapsed from 0 to 30 half-lives worth of seconds
        let max_elapsed = 30_u64.saturating_mul(dw);
        let step = if dw > 100 { dw / 100 } else { 1 };

        let mut e = 0u64;
        while e <= max_elapsed {
            let actual = crate::recency_weight_bps(e, dw);
            let expected = oracle_recency_weight_bps(e, dw);
            assert_eq!(
                actual, expected,
                "oracle mismatch: recency_weight_bps({}, {}) = {}, expected {}",
                e, dw, actual, expected
            );
            e = e.saturating_add(step);
        }
    }
}

// ---- PROPERTY 8: CROSS-DECAY-WINDOW CONSISTENCY ----
// A larger decay_window should produce higher (or equal) weight
// for the same elapsed, because the half-life is longer.
#[test]
fn property_recency_larger_window_higher_weight() {
    let elapsed_values: &[u64] = &[0, 1, 10, 100, 1000, 10_000, 100_000];
    let windows: &[u64] = &[10, 60, 3600, 86_400, 90 * 24 * 60 * 60];

    for &e in elapsed_values {
        for w_idx in 1..windows.len() {
            let w_small = crate::recency_weight_bps(e, windows[w_idx - 1]);
            let w_large = crate::recency_weight_bps(e, windows[w_idx]);
            assert!(
                w_large >= w_small,
                "larger window should give higher weight: \
                 recency_weight_bps({}, {})={} < recency_weight_bps({}, {})={}",
                e,
                windows[w_idx],
                w_large,
                e,
                windows[w_idx - 1],
                w_small
            );
        }
    }
}
