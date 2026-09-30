#![cfg(test)]

use delego_delegation_registry::DelegationError;
use delego_escrow::{
    BatchDepositParams, EscrowConfig, EscrowContract, EscrowContractClient, EscrowError,
    EscrowStatus,
};
use delego_marketplace::{MarketplaceContract, MarketplaceContractClient, MarketplaceError};
use delego_permissions::{
    PermissionError, PermissionStatus, PermissionsContract, PermissionsContractClient,
    RelayedSpendMessage,
};
use delego_reputation::{
    ReputationConfig, ReputationContract, ReputationContractClient, ReputationError,
    TransactionOutcome,
};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::Address as _, testutils::Ledger as _, xdr::ToXdr, Address, BytesN, Env,
    InvokeError, Vec,
};

/// Deterministic test keypair plus its raw ed25519 public key bytes, mirroring
/// `permissions::integration_tests::test_keypair`.
fn test_keypair(env: &Env, seed: u8) -> (SigningKey, BytesN<32>) {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let public_key = BytesN::from_array(env, &signing_key.verifying_key().to_bytes());
    (signing_key, public_key)
}

/// Sign a `RelayedSpendMessage` over its canonical XDR encoding — the exact
/// bytes `execute_spend_via_relayer` re-derives and verifies.
fn sign_relayed_spend(
    env: &Env,
    signing_key: &SigningKey,
    message: RelayedSpendMessage,
) -> BytesN<64> {
    let message_bytes = message.to_xdr(env);
    let len = message_bytes.len() as usize;
    let mut buf = [0u8; 512];
    message_bytes.copy_into_slice(&mut buf[..len]);
    let signature = signing_key.sign(&buf[..len]);
    BytesN::from_array(env, &signature.to_bytes())
}

struct TestEnv {
    env: Env,
    _admin: Address,
    buyer: Address,
    seller: Address,
    agent: Address,
    token_contract_id: Address,
    escrow_contract_id: Address,
    permissions_contract_id: Address,
}

impl TestEnv {
    fn setup() -> Self {
        let env = Env::default();
        env.ledger()
            .with_mut(|l| l.min_persistent_entry_ttl = 518_400);
        env.mock_all_auths_allowing_non_root_auth();

        let admin = Address::generate(&env);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let agent = Address::generate(&env);
        let treasury = Address::generate(&env);

        let token_admin = Address::generate(&env);
        #[allow(deprecated)]
        let token_contract_id = env.register_stellar_asset_contract(token_admin.clone());
        let token_admin_client =
            soroban_sdk::token::StellarAssetClient::new(&env, &token_contract_id);
        token_admin_client.mint(&buyer, &10000);

        let fee_bps = 0u32; // 0% for tests
        let min_amount = 100i128;
        let max_amount = 10000i128;
        let config = EscrowConfig {
            admin: admin.clone(),
            fee_bps,
            treasury,
            min_amount,
            max_amount,
        };
        let escrow_contract_id = env.register(EscrowContract, (config,));
        let permissions_contract_id = env.register(PermissionsContract, ());

        let escrow_client = EscrowContractClient::new(&env, &escrow_contract_id);
        escrow_client.set_security_guardian(&admin, &Address::generate(&env));
        let action = delego_escrow::AdminAction::AddToken(token_contract_id.clone());
        let id = escrow_client.queue_admin_action(&admin, &action);
        let proposal = escrow_client.get_admin_action(&id).unwrap();
        env.ledger().with_mut(|ledger| {
            ledger.sequence_number = proposal.pending.unlock_ledger;
            ledger.timestamp = proposal.unlock_timestamp;
        });
        escrow_client.execute_admin_action(&admin, &id);

        TestEnv {
            env,
            _admin: admin,
            buyer,
            seller,
            agent,
            token_contract_id,
            escrow_contract_id,
            permissions_contract_id,
        }
    }

    fn order_id(&self) -> BytesN<32> {
        BytesN::from_array(&self.env, &[1u8; 32])
    }
}

/// Simulates a delegated purchase: agent executes spend via permissions, then buyer deposits.
fn delegated_deposit(t: &TestEnv, amount: i128, timeout_ledgers: u32) -> u64 {
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);

    perm_client.execute_spend(&t.buyer, &t.agent, &amount, &t.seller);
    escrow_client.deposit(
        &t.buyer,
        &t.seller,
        &t.token_contract_id,
        &amount,
        &t.order_id(),
        &timeout_ledgers,
        &None,
        &None,
    )
}

/// Attempts a delegated purchase: checks permissions and executes spend, then buyer deposits into escrow.
fn try_delegated_deposit(
    t: &TestEnv,
    amount: i128,
    timeout_ledgers: u32,
) -> Result<u64, PermissionError> {
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);

    match perm_client.try_execute_spend(&t.buyer, &t.agent, &amount, &t.seller) {
        Ok(Ok(())) => Ok(escrow_client.deposit(
            &t.buyer,
            &t.seller,
            &t.token_contract_id,
            &amount,
            &t.order_id(),
            &timeout_ledgers,
            &None,
            &None,
        )),
        Err(Ok(e)) => Err(e),
        _ => Err(PermissionError::Unauthorized),
    }
}

#[test]
fn test_permission_checked_before_escrow_fund_fails_without_permission() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);

    // Agent tries to spend without a granted permission.
    let result = perm_client.try_execute_spend(&t.buyer, &t.agent, &200, &t.seller);
    assert_eq!(
        result,
        Err(Ok(delego_permissions::PermissionError::PermissionNotFound))
    );
}

#[test]
fn test_permission_checked_before_escrow_fund_fails_exceeding_limit() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);

    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let merchants = Vec::<soroban_sdk::Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    // Exceeds per-tx limit of 500.
    assert_eq!(
        perm_client.try_execute_spend(&t.buyer, &t.agent, &600, &t.seller),
        Err(Ok(delego_permissions::PermissionError::ExceedsPerTxLimit))
    );
}

#[test]
fn test_permission_checked_before_escrow_fund_succeeds() {
    let t = TestEnv::setup();
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);

    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let merchants = Vec::<soroban_sdk::Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    let escrow_id = delegated_deposit(&t, 400, 3600);

    assert_eq!(escrow_id, 1);
    let record = escrow_client.get_escrow(&escrow_id);
    assert_eq!(record.amount, 400);
}

#[test]
fn test_end_to_end_delegated_purchase() {
    let t = TestEnv::setup();
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let token_client = soroban_sdk::token::Client::new(&t.env, &t.token_contract_id);

    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let mut merchants = Vec::<soroban_sdk::Address>::new(&t.env);
    merchants.push_back(t.seller.clone());

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    let escrow_id = delegated_deposit(&t, 400, 3600);

    assert_eq!(token_client.balance(&t.buyer), 9600);
    assert_eq!(token_client.balance(&t.escrow_contract_id), 400);
    assert_eq!(token_client.balance(&t.seller), 0);

    escrow_client.release(&escrow_id, &t.buyer, &t.seller);

    assert_eq!(token_client.balance(&t.buyer), 9600);
    assert_eq!(token_client.balance(&t.escrow_contract_id), 0);
    assert_eq!(token_client.balance(&t.seller), 400);

    let record = escrow_client.get_escrow(&escrow_id);
    assert!(matches!(record.status, EscrowStatus::Released));
}

/// Simulates the recommended v1 escrow/reputation integration (issue #18):
/// an authorized backend indexer observes the escrow's release and reports
/// the outcome to the reputation contract, rather than escrow calling
/// reputation directly.
#[test]
fn test_reputation_recorded_after_escrow_release() {
    let t = TestEnv::setup();
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);

    let reputation_admin = Address::generate(&t.env);
    let reputation_contract_id = t.env.register(
        ReputationContract,
        (
            reputation_admin.clone(),
            ReputationConfig {
                decay_window_seconds: 90 * 24 * 60 * 60,
                min_transactions_threshold: 1,
                dispute_penalty_bps: 500,
                freeze_threshold_flags: 3,
            },
        ),
    );
    let reputation_client = ReputationContractClient::new(&t.env, &reputation_contract_id);

    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let mut merchants = Vec::<Address>::new(&t.env);
    merchants.push_back(t.seller.clone());
    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    let escrow_id = delegated_deposit(&t, 400, 3600);
    escrow_client.release(&escrow_id, &t.buyer, &t.seller);

    let released = escrow_client.get_escrow(&escrow_id);
    assert!(matches!(released.status, EscrowStatus::Released));

    // Backend indexer relays the observed outcome to the reputation contract.
    reputation_client.record_transaction(
        &reputation_admin,
        &escrow_id,
        &t.seller,
        &t.buyer,
        &released.amount,
        &TransactionOutcome::Released,
    );

    let reputation = reputation_client.get_reputation(&t.seller);
    assert_eq!(reputation.total_transactions, 1);
    assert_eq!(reputation.successful_transactions, 1);
    assert_eq!(reputation.score, 10_000);

    // The buyer, as counterparty, may now rate the seller for this escrow.
    reputation_client.rate_entity(&t.buyer, &escrow_id, &t.seller, &9500u32);
    let breakdown = reputation_client.get_reputation_breakdown(&t.seller, &0u32, &10u32);
    assert_eq!(breakdown.get(0).unwrap().rating, Some(9500u32));
}

#[test]
fn test_permission_revoked_after_spend_before_escrow_deposit_fails() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);

    // Arrange: Grant permission with sufficient allowance.
    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let merchants = Vec::<Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    // Act 1: Agent executes spend within limits.
    perm_client.execute_spend(&t.buyer, &t.agent, &300, &t.seller);
    let perm_record = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(perm_record.spent, 300);

    // Act 2: Owner revokes the permission before escrow deposit.
    perm_client.revoke(&t.buyer, &t.agent);

    // Assert: Permission is no longer active and subsequent spend/deposit fails.
    assert!(!perm_client.is_active(&t.buyer, &t.agent));
    let revoked_record = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(revoked_record.status, PermissionStatus::Revoked);

    let spend_result = perm_client.try_execute_spend(&t.buyer, &t.agent, &200, &t.seller);
    assert_eq!(spend_result, Err(Ok(PermissionError::Unauthorized)));

    let deposit_result = try_delegated_deposit(&t, 200, 3600);
    assert_eq!(deposit_result, Err(PermissionError::Unauthorized));

    assert!(escrow_client.try_get_escrow(&1).is_err());
}

#[test]
fn test_permission_paused_during_flow() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);

    // Arrange: Grant permission and execute first spend + deposit successfully.
    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let merchants = Vec::<Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    let escrow_id_1 = delegated_deposit(&t, 200, 3600);
    assert_eq!(escrow_id_1, 1);
    let perm_1 = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(perm_1.spent, 200);

    // Act 1: Pause the permission mid-flow.
    perm_client.pause(&t.buyer, &t.agent);

    // Assert 1: Permission is paused and subsequent spends fail.
    assert!(!perm_client.is_active(&t.buyer, &t.agent));
    let paused_record = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(paused_record.status, PermissionStatus::Paused);

    let spend_result = perm_client.try_execute_spend(&t.buyer, &t.agent, &200, &t.seller);
    assert_eq!(spend_result, Err(Ok(PermissionError::PermissionPaused)));

    let deposit_result = try_delegated_deposit(&t, 200, 3600);
    assert_eq!(deposit_result, Err(PermissionError::PermissionPaused));

    // Act 2: Resume the permission.
    perm_client.resume(&t.buyer, &t.agent);

    // Assert 2: Permission is active again and spend/deposit succeeds.
    assert!(perm_client.is_active(&t.buyer, &t.agent));
    let resumed_record = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(resumed_record.status, PermissionStatus::Active);

    let escrow_id_2 = delegated_deposit(&t, 200, 3600);
    assert_eq!(escrow_id_2, 2);
    let escrow_record_2 = escrow_client.get_escrow(&escrow_id_2);
    assert_eq!(escrow_record_2.amount, 200);

    let perm_final = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(perm_final.spent, 400);
}

#[test]
fn test_merchant_restriction_enforcement() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);

    // Arrange: Whitelist only seller A.
    let seller_a = t.seller.clone();
    let seller_b = Address::generate(&t.env);

    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 36000u32;
    let mut merchants = Vec::<Address>::new(&t.env);
    merchants.push_back(seller_a.clone());

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    // Act & Assert 1: Attempt spend/deposit to unwhitelisted seller B fails.
    let spend_result = perm_client.try_execute_spend(&t.buyer, &t.agent, &200, &seller_b);
    assert_eq!(spend_result, Err(Ok(PermissionError::MerchantNotAllowed)));

    let can_spend_result = perm_client.try_can_spend(&t.buyer, &t.agent, &200, &seller_b);
    assert_eq!(
        can_spend_result,
        Err(Ok(PermissionError::MerchantNotAllowed))
    );

    // Act & Assert 2: Deposit to allowed seller A succeeds.
    let escrow_id = delegated_deposit(&t, 200, 3600);
    assert_eq!(escrow_id, 1);

    let record = escrow_client.get_escrow(&escrow_id);
    assert_eq!(record.amount, 200);
    assert_eq!(record.seller, seller_a);

    let perm = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(perm.spent, 200);
}

#[test]
fn test_batch_operations_across_contracts() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);
    let token_client = soroban_sdk::token::Client::new(&t.env, &t.token_contract_id);

    // Arrange: Grant permission with high total limit.
    let limit_total = 5000i128;
    let limit_per_tx = 2000i128;
    let ttl_ledgers = 36000u32;
    let merchants = Vec::<Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    let amounts = [300i128, 400i128, 500i128];
    let total_spent: i128 = 1200;

    // Act 1: Execute multiple spends across contracts.
    for &amount in amounts.iter() {
        perm_client.execute_spend(&t.buyer, &t.agent, &amount, &t.seller);
    }

    // Verify cumulative allowance is correctly decremented.
    let perm = perm_client.get_permission(&t.buyer, &t.agent);
    assert_eq!(perm.spent, total_spent);
    assert_eq!(perm.limit_total - perm.spent, 3800);

    // Act 2: Use batch_deposit to create several escrows corresponding to the spends.
    let mut orders = Vec::new(&t.env);
    for (i, &amount) in amounts.iter().enumerate() {
        let order_id = BytesN::from_array(&t.env, &[(i as u8) + 1; 32]);
        orders.push_back(BatchDepositParams {
            seller: t.seller.clone(),
            token: t.token_contract_id.clone(),
            amount,
            order_id,
            timeout_ledgers: 3600,
            order_hash: None,
            schema: None,
        });
    }

    let escrow_ids = escrow_client.batch_deposit(&t.buyer, &orders);

    // Assert: Verify all escrows were created with correct amounts and balances updated.
    assert_eq!(escrow_ids.len(), 3);
    assert_eq!(escrow_ids.get(0).unwrap(), 1);
    assert_eq!(escrow_ids.get(1).unwrap(), 2);
    assert_eq!(escrow_ids.get(2).unwrap(), 3);

    assert_eq!(escrow_client.get_escrow(&1).amount, 300);
    assert_eq!(escrow_client.get_escrow(&2).amount, 400);
    assert_eq!(escrow_client.get_escrow(&3).amount, 500);

    assert_eq!(token_client.balance(&t.buyer), 10000 - total_spent);
    assert_eq!(token_client.balance(&t.escrow_contract_id), total_spent);
}

#[test]
fn test_partial_release_reduces_escrow_state_correctly() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let escrow_client = EscrowContractClient::new(&t.env, &t.escrow_contract_id);
    let token_client = soroban_sdk::token::Client::new(&t.env, &t.token_contract_id);

    // Arrange: Grant permission and deposit 500 into escrow.
    let limit_total = 1000i128;
    let limit_per_tx = 1000i128;
    let ttl_ledgers = 36000u32;
    let merchants = Vec::<Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    let escrow_id = delegated_deposit(&t, 500, 3600);
    assert_eq!(escrow_id, 1);
    assert_eq!(token_client.balance(&t.escrow_contract_id), 500);
    assert_eq!(token_client.balance(&t.seller), 0);

    // Act: Partial-release 200 to the seller.
    let result = escrow_client.partial_release(&escrow_id, &t.buyer, &200);

    // Assert: PartialReleaseResult reflects the partial release.
    assert_eq!(result.released, 200);
    assert_eq!(result.remaining, 300);
    assert!(!result.fully_released);

    // Verify the stored escrow record shows released_amount = 200, remaining balance = 300, and active status.
    let record = escrow_client.get_escrow(&escrow_id);
    assert_eq!(record.released_amount, 200);
    assert_eq!(record.amount - record.released_amount, 300);
    assert_eq!(record.status, EscrowStatus::Funded);

    // Verify token transfers: seller received 200, escrow contract retains 300.
    assert_eq!(token_client.balance(&t.seller), 200);
    assert_eq!(token_client.balance(&t.escrow_contract_id), 300);
}

#[test]
fn test_permission_expiry_between_grant_and_spend() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);

    // Arrange: Grant permission with a very short TTL.
    let limit_total = 1000i128;
    let limit_per_tx = 500i128;
    let ttl_ledgers = 10u32;
    let merchants = Vec::<Address>::new(&t.env);

    perm_client.grant(
        &t.buyer,
        &t.agent,
        &limit_total,
        &limit_per_tx,
        &merchants,
        &ttl_ledgers,
    );

    // Permission is active before expiration.
    assert!(perm_client.is_active(&t.buyer, &t.agent));
    assert_eq!(
        perm_client.try_can_spend(&t.buyer, &t.agent, &200, &t.seller),
        Ok(Ok(()))
    );

    // Act: Advance the ledger sequence past the expiry.
    let current_seq = t.env.ledger().sequence();
    t.env.ledger().with_mut(|li| {
        li.sequence_number = current_seq + ttl_ledgers + 1;
    });

    // Assert: Permission is no longer active, and spend attempt fails with Expired.
    assert!(!perm_client.is_active(&t.buyer, &t.agent));

    let spend_result = perm_client.try_execute_spend(&t.buyer, &t.agent, &200, &t.seller);
    assert_eq!(spend_result, Err(Ok(PermissionError::Expired)));

    let can_spend_result = perm_client.try_can_spend(&t.buyer, &t.agent, &200, &t.seller);
    assert_eq!(can_spend_result, Err(Ok(PermissionError::Expired)));

    let deposit_result = try_delegated_deposit(&t, 200, 3600);
    assert_eq!(deposit_result, Err(PermissionError::Expired));
}

// ------------------------------------------------------------------------
// Security-control coverage: velocity, relayer replay, and multi-owner
// quorum, wired into the same cross-contract suite as the escrow/permission
// happy paths above. Whitelist gating end-to-end is already covered by
// `test_merchant_restriction_enforcement`.
// ------------------------------------------------------------------------

#[test]
fn test_second_velocity_spend_fails() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);

    let merchants = Vec::<Address>::new(&t.env);
    perm_client.grant(&t.buyer, &t.agent, &1000, &500, &merchants, &36000u32);

    perm_client.set_admin(&t._admin);
    perm_client.set_velocity_limit(&t._admin, &50u32);

    // First spend succeeds and records the current ledger for velocity tracking.
    perm_client.execute_spend(&t.buyer, &t.agent, &100, &t.seller);

    // A second spend before the configured interval has elapsed is rejected.
    let second = perm_client.try_execute_spend(&t.buyer, &t.agent, &100, &t.seller);
    assert_eq!(second, Err(Ok(PermissionError::VelocityLimitExceeded)));

    // Advancing past the interval allows spending again.
    let current_seq = t.env.ledger().sequence();
    t.env.ledger().with_mut(|li| {
        li.sequence_number = current_seq + 51;
    });
    perm_client.execute_spend(&t.buyer, &t.agent, &100, &t.seller);
    assert_eq!(perm_client.get_permission(&t.buyer, &t.agent).spent, 200);
}

#[test]
fn test_relayed_spend_replay_with_old_nonce_reverts() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let relayer = Address::generate(&t.env);

    let merchants = Vec::<Address>::new(&t.env);
    perm_client.grant(&t.buyer, &t.agent, &1000, &500, &merchants, &36000u32);

    let (signing_key, public_key) = test_keypair(&t.env, 7);
    perm_client.set_relayer_key(&t.agent, &public_key);

    let expiration_ledger = t.env.ledger().sequence() + 1000;
    let message = RelayedSpendMessage {
        owner: t.buyer.clone(),
        delegate: t.agent.clone(),
        merchant: t.seller.clone(),
        amount: 100,
        nonce: 0,
        expiration_ledger,
        epoch: 0,
    };
    let signature = sign_relayed_spend(&t.env, &signing_key, message);

    perm_client.execute_spend_via_relayer(
        &relayer,
        &t.buyer,
        &t.agent,
        &100,
        &t.seller,
        &0u64,
        &expiration_ledger,
        &0u32,
        &signature,
    );
    assert_eq!(perm_client.get_relayer_nonce(&t.buyer, &t.agent), 1);

    // Replaying the same signed message (nonce 0 again) is rejected — the
    // delegate's expected nonce has already advanced to 1.
    let replay = perm_client.try_execute_spend_via_relayer(
        &relayer,
        &t.buyer,
        &t.agent,
        &100,
        &t.seller,
        &0u64,
        &expiration_ledger,
        &0u32,
        &signature,
    );
    assert_eq!(replay, Err(Ok(PermissionError::InvalidNonce)));
}

#[test]
fn test_multi_owner_spend_enforces_quorum() {
    let t = TestEnv::setup();
    let perm_client = PermissionsContractClient::new(&t.env, &t.permissions_contract_id);
    let owner_b = Address::generate(&t.env);
    let owner_c = Address::generate(&t.env);

    let mut owners = Vec::<Address>::new(&t.env);
    owners.push_back(t.buyer.clone());
    owners.push_back(owner_b.clone());
    owners.push_back(owner_c.clone());
    let merchants = Vec::<Address>::new(&t.env);

    perm_client.grant_multi_owner(
        &t.buyer, &owners, &t.agent, &1000, &500, &merchants, &36000u32, &2u32,
    );

    // A single signer cannot satisfy a 2-of-3 threshold.
    let mut one_signer = Vec::<Address>::new(&t.env);
    one_signer.push_back(t.buyer.clone());
    let under_quorum =
        perm_client.try_execute_spend_multi(&t.buyer, &t.agent, &one_signer, &100, &t.seller);
    assert_eq!(
        under_quorum,
        Err(Ok(PermissionError::InsufficientSignatures))
    );

    // Two of the three registered owners satisfies the threshold.
    let mut two_signers = Vec::<Address>::new(&t.env);
    two_signers.push_back(t.buyer.clone());
    two_signers.push_back(owner_b.clone());
    perm_client.execute_spend_multi(&t.buyer, &t.agent, &two_signers, &100, &t.seller);

    let record = perm_client.get_multi_permission(&t.buyer, &t.agent);
    assert_eq!(record.spent, 100);
}

/// Cross-contract error-code allocation.
///
/// The bridge-facing error space is a single numeric `u32` code space. To make
/// numeric codes unambiguous, every code belongs to at most one contract's
/// error enum.
///
/// | Contract      | Error enum          |
/// |---------------|---------------------|
/// | Escrow        | `EscrowError`       |
/// | Permissions   | `PermissionError`   |
/// | Reputation    | `ReputationError`   |
/// | Delegation    | `DelegationError`   |
/// | Marketplace   | `MarketplaceError`  |
///
/// The test below verifies this uniqueness property for all codes accepted by
/// each contract's `TryFrom<InvokeError>` implementation.
fn collect_error_codes<T>() -> std::vec::Vec<u32>
where
    T: TryFrom<InvokeError>,
{
    // Scan wide enough to cover all current error code allocations:
    // - EscrowError:      1..=999        (legacy)
    // - PermissionError:  1_000..=2_999
    // - ReputationError:  0x0003_0001..=0x0003_FFFF  (~196K)
    // - DelegationError:  3_000..=3_999
    // - MarketplaceError: 4_000..=4_999
    // We scan to 0x000F_FFFF (1_048_575) to cover all current and near-future allocations.
    (0..=0x000F_FFFFu32)
        .filter(|&code| T::try_from(InvokeError::Contract(code)).is_ok())
        .collect()
}

#[test]
fn test_error_codes_are_unique_across_contracts() {
    let error_codes = [
        ("escrow", collect_error_codes::<EscrowError>()),
        ("permissions", collect_error_codes::<PermissionError>()),
        ("reputation", collect_error_codes::<ReputationError>()),
        ("delegation", collect_error_codes::<DelegationError>()),
        ("marketplace", collect_error_codes::<MarketplaceError>()),
    ];

    let mut seen = std::collections::BTreeSet::new();
    for (contract_name, codes) in error_codes {
        assert!(
            !codes.is_empty(),
            "{contract_name} must expose at least one error code"
        );
        for code in codes {
            assert!(
                seen.insert(code),
                "error code {code} is shared with another contract"
            );
        }
    }
}
I2AhW2NmZyh0ZXN0KV0KCnVzZSBkZWxlZ29fZGVsZWdhdGlvbl9yZWdpc3RyeTo6RGVsZWdhdGlvbkVycm9yOwp1c2UgZGVsZWdvX2VzY3Jvdzo6ewogICAgQmF0Y2hEZXBvc2l0UGFyYW1zLCBFc2Nyb3dDb25maWcsIEVzY3Jvd0NvbnRyYWN0LCBFc2Nyb3dDb250cmFjdENsaWVudCwgRXNjcm93RXJyb3IsCiAgICBFc2Nyb3dTdGF0dXMsCn07CnVzZSBkZWxlZ29fbWFya2V0cGxhY2U6OntNYXJrZXRwbGFjZUNvbnRyYWN0LCBNYXJrZXRwbGFjZUNvbnRyYWN0Q2xpZW50LCBNYXJrZXRwbGFjZUVycm9yfTsKdXNlIGRlbGVnb19wZXJtaXNzaW9uczo6ewogICAgUGVybWlzc2lvbkVycm9yLCBQZXJtaXNzaW9uU3RhdHVzLCBQZXJtaXNzaW9uc0NvbnRyYWN0LCBQZXJtaXNzaW9uc0NvbnRyYWN0Q2xpZW50LAogICAgUmVsYXllZFNwZW5kTWVzc2FnZSwKfTsKdXNlIGRlbGVnb19yZXB1dGF0aW9uOjp7CiAgICBSZXB1dGF0aW9uQ29uZmlnLCBSZXB1dGF0aW9uQ29udHJhY3QsIFJlcHV0YXRpb25Db250cmFjdENsaWVudCwgUmVwdXRhdGlvbkVycm9yLAogICAgVHJhbnNhY3Rpb25PdXRjb21lLAp9Owp1c2UgZWQyNTUxOV9kYWxlayB2ZXJpZnk6OnN0ZDo6VmVyaWZ5S2V5Owp1c2UgZWQyNTUxOV9kYWxlayB2ZXJpZnk6OnN0ZDo6U2lnbmF0dXJlIGFzIERhbGVrU2lnbmF0dXJlOwp1c2UgZWQyNTUxOV9kYWxlayB2ZXJpZnk6OnN0ZDo6U2lnbmluZ0tleTsKdXNlIGVkMjU1MTlfZGFsZWs6OlNpZ25lcjsKdXNlIHNvcm9iYW5fc2RrOjp7CiAgICB0ZXN0dXRpbHM6OkFkZHJlc3MgYXMgXywgdGVzdHV0aWxzOjpMZWRnZXIgYXMgXywgeGRyOjpUb1hkciwgQWRkcmVzcywgQnl0ZXNOLCBFbnYsCiAgICBJbnZva2VFcnJvciwgVmVjLAp9OwoKLy8vIERldGVybWluaXN0aWMgdGVzdCBrZXlwYWlyIHBsdXMgaXRzIHJhdyBlZDI1NTE5IHB1YmxpYyBrZXkgYnl0ZXMsIG1pcnJvcmluZwovLy8gYHBlcm1pc3Npb25zOjppbnRlZ3JhdGlvbl90ZXN0czo6dGVzdF9rZXlwYWlyYC4KZm4gdGVzdF9rZXlwYWlyKGVudjogJkVudiwgc2VlZDogdTgpIC0+IChTaWduaW5nS2V5LCBCeXRlc048MzI+KSB7CiAgICBsZXQgc2lnbmluZ19rZXkgPSBTaWduaW5nS2V5Ojpmcm9tX2J5dGVzKCZbc2VlZDsgMzJdKTsKICAgIGxldCBwdWJsaWNfa2V5ID0gQnl0ZXNOPjo6ZnJvbV9hcnJheShlbnYsICZzaWduaW5nX2tleS52ZXJpZnlpbmdfa2V5KCkudG9fYnl0ZXMoKSk7CiAgICAoc2lnbmluZ19rZXksIHB1YmxpY19rZXkpCn0KCi8vLyBTaWduIGEgYFJlbGF5ZWRTcGVuZE1lc3NhZ2VgIG92ZXIgaXRzIGNhbm9uaWNhbCBYRFIgZW5jb2Rpbmcg4oCUIHRoZSBleGFjdAovLy8gYnl0ZXMgYGV4ZWN1dGVfc3BlbmRfdmlhX3JlbGF5ZXJgIHJlLWRlcml2ZXMgYW5kIHZlcmlmaWVzLgpmbiBzaWduX3JlbGF5ZWRfc3BlbmQoCiAgICBlbnY6ICZFbnYsCiAgICBzaWduaW5nX2tleTogJlNpZ25pbmdLZXksCiAgICBtZXNzYWdlOiBSZWxheWVkU3BlbmRNZXNzYWdlLAopIC0+IEJ5dGVzTjw2ND4gewogICAgbGV0IG1lc3NhZ2VfYnl0ZXMgPSBtZXNzYWdlLnRvX3hkcihlbnYpOwogICAgbGV0IGxlbiA9IG1lc3NhZ2VfYnl0ZXMubGVuKCkgYXMgdXNpemU7CiAgICBsZXQgbXV0IGJ1ZiA9IFswdTg7IDUxMl07CiAgICBtZXNzYWdlX2J5dGVzLmNvcHlfaW50b19zbGljZSgmbXV0IGJ1ZlsuLmxlbl0pOwogICAgbGV0IHNpZ25hdHVyZSA9IHNpZ25pbmdfa2V5LnNpZ24oJmJ1ZlsuLmxlbl0pOwogICAgQnl0ZXNOPjo6ZnJvbV9hcnJheShlbnYsICZzaWduYXR1cmUudG9fYnl0ZXMoKSkKfQoKc3RydWN0IFRlc3RFbnYgewogICAgZW52OiBFbnYsCiAgICBfYWRtaW46IEFkZHJlc3MsCiAgICBidXllcjogQWRkcmVzcywKICAgIHNlbGxlcjogQWRkcmVzcywKICAgIGFnZW50OiBBZGRyZXNzLAogICAgdG9rZW5fY29udHJhY3RfaWQ6IEFkZHJlc3MsCiAgICBlc2Nyb3dfY29udHJhY3RfaWQ6IEFkZHJlc3MsCiAgICBwZXJtaXNzaW9uc19jb250cmFjdF9pZDogQWRkcmVzcywKfQoKaW1wbCBUZXN0RW52IHsKICAgIGZuIHNldHVwKCkgLT4gU2VsZiB7CiAgICAgICAgbGV0IGVudiA9IEVudjo6ZGVmYXVsdCgpOwogICAgICAgIGVudi5tb2NrX2FsbF9hdXRoc19hbGxvd2luZ19ub25fcm9vdF9hdXRoKCk7CgogICAgICAgIGxldCBhZG1pbiA9IEFkZHJlc3M6OmdlbmVyYXRlKCZlbnYpOwogICAgICAgIGxldCBidXllciA9IEFkZHJlc3M6OmdlbmVyYXRlKCZlbnYpOwogICAgICAgIGxldCBzZWxsZXIgPSBBZGRyZXNzOjpnZW5lcmF0ZSgmZW52KTsKICAgICAgICBsZXQgYWdlbnQgPSBBZGRyZXNzOjpnZW5lcmF0ZSgmZW52KTsKICAgICAgICBsZXQgdHJlYXN1cnkgPSBBZGRyZXNzOjpnZW5lcmF0ZSgmZW52KTsKCiAgICAgICAgbGV0IHRva2VuX2FkbWluID0gQWRkcmVzczo6Z2VuZXJhdGUoJmVudik7CiAgICAgICAgI1thbGxvd1tkZXByZWNhdGVkXV0KICAgICAgICBsZXQgdG9rZW5fY29udHJhY3RfaWQgPSBlbnYucmVnaXN0ZXJfc3RlbGxhcl9hc3NldF9jb250cmFjdCh0b2tlbl9hZG1pbi5jbG9uZSgpKTsKICAgICAgICBsZXQgdG9rZW5fYWRtaW5fY2xpZW50ID0KICAgICAgICAgICAgc29yb2Jhbl9zZGs6OnRva2VuOjpTdGVsbGFyQXNzZXRDbGllbnQ6Om5ldygmZW52LCAmdG9rZW5fY29udHJhY3RfaWQpOwogICAgICAgIHRva2VuX2FkbWluX2NsaWVudC5taW50KCZidXllciwgJjEwMDAwKTsKCiAgICAgICAgbGV0IGZlZV9icHMgPSAwdTMyOyAvLyAwJSBmb3IgdGVzdHMKICAgICAgICBsZXQgbWluX2Ftb3VudCA9IDEwMGkxMjg7CiAgICAgICAgbGV0IG1heF9hbW91bnQgPSAxMDAwMGkxMjg7CiAgICAgICAgbGV0IGNvbmZpZyA9IEVzY3Jvd0NvbmZpZyB7CiAgICAgICAgICAgIGFkbWluOiBhZG1pbi5jbG9uZSgpLAogICAgICAgICAgICBmZWVfYnBzLAogICAgICAgICAgICB0cmVhc3VyeSwKICAgICAgICAgICAgbWluX2Ftb3VudCwKICAgICAgICAgICAgbWF4X2Ftb3VudCwKICAgICAgICB9OwogICAgICAgIGxldCBlc2Nyb3dfY29udHJhY3RfaWQgPSBlbnYucmVnaXN0ZXIoRXNjcm93Q29udHJhY3QsIChjb25maWcsKSk7CiAgICAgICAgbGV0IHBlcm1pc3Npb25zX2NvbnRyYWN0X2lkID0gZW52LnJlZ2lzdGVyKFBlcm1pc3Npb25zQ29udHJhY3QsICgpKTsKCiAgICAgICAgbGV0IGVzY3Jvd19jbGllbnQgPSBFc2Nyb3dDb250cmFjdENsaWVudDo6bmV3KCZlbnYsICZlc2Nyb3dfY29udHJhY3RfaWQpOwogICAgICAgIGVzY3Jvd19jbGllbnQuYWRkX3Rva2VuKCZhZG1pbiwgJnRva2VuX2NvbnRyYWN0X2lkKTsKCiAgICAgICAgVGVzdEVudiB7CiAgICAgICAgICAgIGVudiwKICAgICAgICAgICAgX2FkbWluOiBhZG1pbiwKICAgICAgICAgICAgYnV5ZXIsCiAgICAgICAgICAgIHNlbGxlciwKICAgICAgICAgICAgYWdlbnQsCiAgICAgICAgICAgIHRva2VuX2NvbnRyYWN0X2lkLAogICAgICAgICAgICBlc2Nyb3dfY29udHJhY3RfaWQsCiAgICAgICAgICAgIHBlcm1pc3Npb25zX2NvbnRyYWN0X2lkLAogICAgICAgIH0KICAgIH0KCiAgICBmbiBvcmRlcl9pZCgmc2VsZikgLT4gQnl0ZXNOPDMyPiB7CiAgICAgICAgQnl0ZXNOPjo6ZnJvbV9hcnJheSgmc2VsZi5lbnYsICZbMXV1ODsgMzJdKQogICAgfQp9CgovLy8gU2ltdWxhdGVzIGEgZGVsZWdhdGVkIHB1cmNoYXNlOiBhZ2VudCBleGVjdXRlcyBzcGVuZCB2aWEgcGVybWlzc2lvbnMsIHRoZW4gYnV5ZXIgZGVwb3NpdHMuCmZuIGRlbGVnYXRlZF9kZXBvc2l0KHQ6ICZUZXN0RW52LCBhbW91bnQ6IGkxMjgsIHRpbWVvdXRfbGVkZ2VyczogdTMyKSAtPiB1NjQgewogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwogICAgbGV0IGVzY3Jvd19jbGllbnQgPSBFc2Nyb3dDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQuZXNjcm93X2NvbnRyYWN0X2lkKTsKCiAgICBwZXJtX2NsaWVudC5leGVjdXRlX3NwZW5kKCZ0LmJ1eWVyLCAmdC5hZ2VudCwgJmFtb3VudCwgJnQuc2VsbGVyKTsKICAgIGVzY3Jvd19jbGllbnQuZGVwb3NpdCgKICAgICAgICAmdC5idXllciwKICAgICAgICAmdC5zZWxsZXIsCiAgICAgICAgJnQudG9rZW5fY29udHJhY3RfaWQsCiAgICAgICAgJmFtb3VudCwKICAgICAgICAmdC5vcmRlcl9pZCgpLAogICAgICAgICZ0aW1lb3V0X2xlZGdlcnMsCiAgICAgICAgJk5vbmUsCiAgICAgICAgJk5vbmUsCiAgICApCn0KCi8vLyBBdHRlbXB0cyBhIGRlbGVnYXRlZCBwdXJjaGFzZTogY2hlY2tzIHBlcm1pc3Npb25zIGFuZCBleGVjdXRlcyBzcGVuZCwgdGhlbiBidXllciBkZXBvc2l0cyBpbnRvIGVzY3Jvdy4KZm4gdHJ5X2RlbGVnYXRlZF9kZXBvc2l0KAogICAgdDogJlRlc3RFbnYsCiAgICBhbW91bnQ6IGkxMjgsCiAgICB0aW1lb3V0X2xlZGdlcnM6IHUzMiwKKSAtPiBSZXN1bHQ8dTY0LCBQZXJtaXNzaW9uRXJyb3I+IHsKICAgIGxldCBwZXJtX2NsaWVudCA9IFBlcm1pc3Npb25zQ29udHJhY3RDbGllbnQ6Om5ldygmdC5lbnYsICZ0LnBlcm1pc3Npb25zX2NvbnRyYWN0X2lkKTsKICAgIGxldCBlc2Nyb3dfY2xpZW50ID0gRXNjcm93Q29udHJhY3RDbGllbnQ6Om5ldygmdC5lbnYsICZ0LmVzY3Jvd19jb250cmFjdF9pZCk7CgogICAgbWF0Y2ggcGVybV9jbGllbnQudHJ5X2V4ZWN1dGVfc3BlbmQoJnQuYnV5ZXIsICZ0LmFnZW50LCAmYW1vdW50LCAmdC5zZWxsZXIpIHsKICAgICAgICBPayhPaygoKSkgPT4gT2soZXNjcm93X2NsaWVudC5kZXBvc2l0KAogICAgICAgICAgICAmdC5idXllciwKICAgICAgICAgICAgJnQuc2VsbGVyLAogICAgICAgICAgICAmdC50b2tlbl9jb250cmFjdF9pZCwKICAgICAgICAgICAgJmFtb3VudCwKICAgICAgICAgICAgJnQub3JkZXJfaWQoKSwKICAgICAgICAgICAgJnRpbWVvdXRfbGVkZ2VycywKICAgICAgICAgICAgJk5vbmUsCiAgICAgICAgICAgICZOb25lLAogICAgICAgICkpLAogICAgICAgIEVycihPayhlKSkgPT4gRXJyKGUpLAogICAgICAgIF8gPT4gRXJyKFBlcm1pc3Npb25FcnJvcjo6VW5hdXRob3JpemVkKSwKICAgIH0KfQoKI1t0ZXN0XQpmbiB0ZXN0X3Blcm1pc3Npb25fY2hlY2tlZF9iZWZvcmVfZXNjcm93X2Z1bmRfZmFpbHNfd2l0aG91dF9wZXJtaXNzaW9uKCkgewogICAgbGV0IHQgPSBUZXN0RW52OjpzZXR1cCgpOwogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwoKICAgIC8vIEFnZW50IHRyaWVzIHRvIHNwZW5kIHdpdGhvdXQgYSBncmFudGVkIHBlcm1pc3Npb24uCiAgICBsZXQgcmVzdWx0ID0gcGVybV9jbGllbnQudHJ5X2V4ZWN1dGVfc3BlbmQoJnQuYnV5ZXIsICZ0LmFnZW50LCAmMjAwLCAmdC5zZWxsZXIpOwogICAgYXNzZXJ0X2VxISgKICAgICAgICByZXN1bHQsCiAgICAgICAgRXJyKE9rKGRlbGVnb19wZXJtaXNzaW9uczo6UGVybWlzc2lvbkVycm9yOjpQZXJtaXNzaW9uTm90Rm91bmQpKQogICAgKTsKfQoKI1t0ZXN0XQpmbiB0ZXN0X3Blcm1pc3Npb25fY2hlY2tlZF9iZWZvcmVfZXNjcm93X2Z1bmRfZmFpbHNfZXhjZWVkaW5nX2xpbWl0KCkgewogICAgbGV0IHQgPSBUZXN0RW52OjpzZXR1cCgpOwogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwoKICAgIGxldCBsaW1pdF90b3RhbCA9IDEwMDBpMTI4OwogICAgbGV0IGxpbWl0X3Blcl90eCA9IDUwMGkxMjg7CiAgICBsZXQgdHRsX2xlZGdlcnMgPSAzNjAwMHUzMjsKICAgIGxldCBtZXJjaGFudHMgPSBWZWM6Ojxzcm9iYW5fc2RrOjpBZGRyZXNzPjo6bmV3KCZ0LmVudik7CgogICAgcGVybV9jbGllbnQuZ3JhbnQoCiAgICAgICAgJnQuYnV5ZXIsCiAgICAgICAgJnQuYWdlbnQsCiAgICAgICAgJmxpbWl0X3RvdGFsLAogICAgICAgICZsaW1pdF9wZXJfdHgsCiAgICAgICAgJm1lcmNoYW50cywKICAgICAgICAmdHRsX2xlZGdlcnMsCiAgICApOwoKICAgIC8vIEV4Y2VlZHMgcGVyLXR4IGxpbWl0IG9mIDUwMC4KICAgIGFzc2VydF9lcSEoCiAgICAgICAgcGVybV9jbGllbnQudHJ5X2V4ZWN1dGVfc3BlbmQoJnQuYnV5ZXIsICZ0LmFnZW50LCAmNjAwLCAmdC5zZWxsZXIpLAogICAgICAgIEVycihPayhkZWxlZ29fcGVybWlzc2lvbnM6OlBlcm1pc3Npb25FcnJvcjo6RXhjZWVkc1BlclR4TGltaXQpKQogICAgKTsKfQoKI1t0ZXN0XQpmbiB0ZXN0X3Blcm1pc3Npb25fY2hlY2tlZF9iZWZvcmVfZXNjcm93X2Z1bmRfc3VjY2VlZHMoKSB7CiAgICBsZXQgdCA9IFRlc3RFbnY6OnNldHVwKCk7CiAgICBsZXQgZXNjcm93X2NsaWVudCA9IEVzY3Jvd0NvbnRyYWN0Q2xpZW50OjpuZXcoJnQuZW52LCAmdC5lc2Nyb3dfY29udHJhY3RfaWQpOwogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwoKICAgIGxldCBsaW1pdF90b3RhbCA9IDEwMDBpMTI4OwogICAgbGV0IGxpbWl0X3Blcl90eCA9IDUwMGkxMjg7CiAgICBsZXQgdHRsX2xlZGdlcnMgPSAzNjAwMHUzMjsKICAgIGxldCBtZXJjaGFudHMgPSBWZWM6Ojxzcm9iYW5fc2RrOjpBZGRyZXNzPjo6bmV3KCZ0LmVudik7CgogICAgcGVybV9jbGllbnQuZ3JhbnQoCiAgICAgICAgJnQuYnV5ZXIsCiAgICAgICAgJnQuYWdlbnQsCiAgICAgICAgJmxpbWl0X3RvdGFsLAogICAgICAgICZsaW1pdF9wZXJfdHgsCiAgICAgICAgJm1lcmNoYW50cywKICAgICAgICAmdHRsX2xlZGdlcnMsCiAgICApOwoKICAgIGxldCBlc2Nyb3dfaWQgPSBkZWxlZ2F0ZWRfZGVwb3NpdCgmdCwgNDAwLCAzNjAwKTsKCiAgICBhc3NlcnRfZXEhKGVzY3Jvd19pZCwgMSk7CiAgICBsZXQgcmVjb3JkID0gZXNjcm93X2NsaWVudC5nZXRfZXNjcm93KCZlc2Nyb3dfaWQpOwogICAgYXNzZXJ0X2VxIShyZWNvcmQuYW1vdW50LCA0MDApOwp9CgojW3Rlc3RdCmZuIHRlc3RfZW5kX3RvX2VuZF9kZWxlZ2F0ZWRfcHVyY2hhc2UoKSB7CiAgICBsZXQgdCA9IFRlc3RFbnY6OnNldHVwKCk7CiAgICBsZXQgZXNjcm93X2NsaWVudCA9IEVzY3Jvd0NvbnRyYWN0Q2xpZW50OjpuZXcoJnQuZW52LCAmdC5lc2Nyb3dfY29udHJhY3RfaWQpOwogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwogICAgbGV0IHRva2VuX2NsaWVudCA9IHNvcm9iYW5fc2RrOjp0b2tlbjo6Q2xpZW50OjpuZXcoJnQuZW52LCAmdC50b2tlbl9jb250cmFjdF9pZCk7CgogICAgbGV0IGxpbWl0X3RvdGFsID0gMTAwMGkxMjg7CiAgICBsZXQgbGltaXRfcGVyX3R4ID0gNTAwaTEyODsKICAgIGxldCB0dGxfbGVkZ2VycyA9IDM2MDAwdTMyOwogICAgbGV0IG11dCBtZXJjaGFudHMgPSBWZWM6OjxBZGRyZXNzPjo6bmV3KCZ0LmVudik7CiAgICBtZXJjaGFudHMucHVzaF9iYWNrKHQuc2VsbGVyLmNsb25lKCkpOwoKICAgIHBlcm1fY2xpZW50LmdyYW50KAogICAgICAgICZ0LmJ1eWVyLAogICAgICAgICZ0LmFnZW50LAogICAgICAgICZsaW1pdF90b3RhbCwKICAgICAgICAmbGltaXRfcGVyX3R4LAogICAgICAgICZtZXJjaGFudHMsCiAgICAgICAgJnR0bF9sZWRnZXJzLAogICAgKTsKCiAgICBsZXQgZXNjcm93X2lkID0gZGVsZWdhdGVkX2RlcG9zaXQoJnQsIDQwMCwgMzYwMCk7CgogICAgYXNzZXJ0X2VxISh0b2tlbl9jbGllbnQuYmFsYW5jZSgmdC5idXllciksIDk2MDApOwogICAgYXNzZXJ0X2VxISh0b2tlbl9jbGllbnQuYmFsYW5jZSgmdC5lc2Nyb3dfY29udHJhY3RfaWQpLCA0MDApOwogICAgYXNzZXJ0X2VxISh0b2tlbl9jbGllbnQuYmFsYW5jZSgmdC5zZWxsZXIpLCAwKTsKCiAgICBlc2Nyb3dfY2xpZW50LnJlbGVhc2UoJmVzY3Jvd19pZCwgJnQuYnV5ZXIsICZ0LnNlbGxlcik7CgogICAgYXNzZXJ0X2VxISh0b2tlbl9jbGllbnQuYmFsYW5jZSgmdC5idXllciksIDk2MDApOwogICAgYXNzZXJ0X2VxISh0b2tlbl9jbGllbnQuYmFsYW5jZSgmdC5lc2Nyb3dfY29udHJhY3RfaWQpLCAwKTsKICAgIGFzc2VydF9lcSEodG9rZW5fY2xpZW50LmJhbGFuY2UoJnQuc2VsbGVyKSwgNDAwKTsKCiAgICBsZXQgcmVjb3JkID0gZXNjcm93X2NsaWVudC5nZXRfZXNjcm93KCZlc2Nyb3dfaWQpOwogICAgYXNzZXJ0IShtYXRjaGVzIShyZWNvcmQuc3RhdHVzLCBFc2Nyb3dTdGF0dXM6OlJlbGVhc2VkKSk7Cn0KCi8vLyBTaW11bGF0ZXMgdGhlIHJlY29tbWVuZGVkIHYxIGVzY3Jvdy9yZXB1dGF0aW9uIGludGVncmF0aW9uIChpc3N1ZSAjMTgpOgovLy8gYW4gYXV0aG9yaXplZCBiYWNrZW5kIGluZGV4ZXIgb2JzZXJ2ZXMgdGhlIGVzY3JvdyBzIHJlbGVhc2UgYW5kIHJlcG9ydHMKLy8vIHRoZSBvdXRjb21lIHRvIHRoZSByZXB1dGF0aW9uIGNvbnRyYWN0LCByYXRoZXIgdGhhbiBlc2Nyb3cgY2FsbGluZwovLy8gcmVwdXRhdGlvbiBkaXJlY3RseS4KI1t0ZXN0XQpmbiB0ZXN0X3JlcHV0YXRpb25fcmVjb3JkZWRfYWZ0ZXJfZXNjcm93X3JlbGVhc2UoKSB7CiAgICBsZXQgdCA9IFRlc3RFbnY6OnNldHVwKCk7CiAgICBsZXQgZXNjcm93X2NsaWVudCA9IEVzY3Jvd0NvbnRyYWN0Q2xpZW50OjpuZXcoJnQuZW52LCAmdC5lc2Nyb3dfY29udHJhY3RfaWQpOwogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwoKICAgIGxldCByZXB1dGF0aW9uX2FkbWluID0gQWRkcmVzczo6Z2VuZXJhdGUoJnQuZW52KTsKICAgIGxldCByZXB1dGF0aW9uX2NvbnRyYWN0X2lkID0gdC5lbnYucmVnaXN0ZXIoCiAgICAgICAgUmVwdXRhdGlvbkNvbnRyYWN0LAogICAgICAgICgKICAgICAgICAgICAgcmVwdXRhdGlvbl9hZG1pbi5jbG9uZSgpLAogICAgICAgICAgICBSZXB1dGF0aW9uQ29uZmlnIHsKICAgICAgICAgICAgICAgIGRlY2F5X3dpbmRvd19zZWNvbmRzOiA5MCAqIDI0ICogNjAgKiA2MCwKICAgICAgICAgICAgICAgIG1pbl90cmFuc2FjdGlvbnNfdGhyZXNob2xkOiAxLAogICAgICAgICAgICAgICAgZGlzcHV0ZV9wZW5hbHR5X2JwczogNTAwLAogICAgICAgICAgICAgICAgZnJlZXplX3RocmVzaG9sZF9mbGFnczogMywKICAgICAgICAgICAgfSwKICAgICAgICApLAogICAgKTsKICAgIGxldCByZXB1dGF0aW9uX2NsaWVudCA9IFJlcHV0YXRpb25Db250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnJlcHV0YXRpb25fY29udHJhY3RfaWQpOwoKICAgIGxldCBsaW1pdF90b3RhbCA9IDEwMDBpMTI4OwogICAgbGV0IGxpbWl0X3Blcl90eCA9IDUwMGkxMjg7CiAgICBsZXQgdHRsX2xlZGdlcnMgPSAzNjAwMHUzMjsKICAgIGxldCBtdXQgbWVyY2hhbnRzID0gVmVjOjo8QWRkcmVzcz46Om5ldygmdC5lbnYpOwogICAgbWVyY2hhbnRzLnB1c2hfYmFjayh0LnNlbGxlci5jbG9uZSgpKTsKICAgIHBlcm1fY2xpZW50LmdyYW50KAogICAgICAgICZ0LmJ1eWVyLAogICAgICAgICZ0LmFnZW50LAogICAgICAgICZsaW1pdF90b3RhbCwKICAgICAgICAmbGltaXRfcGVyX3R4LAogICAgICAgICZtZXJjaGFudHMsCiAgICAgICAgJnR0bF9sZWRnZXJzLAogICAgKTsKCiAgICBsZXQgZXNjcm93X2lkID0gZGVsZWdhdGVkX2RlcG9zaXQoJnQsIDQwMCwgMzYwMCk7CiAgICBlc2Nyb3dfY2xpZW50LnJlbGVhc2UoJmVzY3Jvd19pZCwgJnQuYnV5ZXIsICZ0LnNlbGxlcik7CgogICAgbGV0IHJlbGVhc2VkID0gZXNjcm93X2NsaWVudC5nZXRfZXNjcm93KCZlc2Nyb3dfaWQpOwogICAgYXNzZXJ0IShtYXRjaGVzIShyZWxlYXNlZC5zdGF0dXMsIEVzY3Jvd1N0YXR1czo6UmVsZWFzZWQpKTsKCiAgICAvLyBCYWNrZW5kIGluZGV4ZXIgcmVsYXlzIHRoZSBvYnNlcnZlZCBvdXRjb21lIHRvIHRoZSByZXB1dGF0aW9uIGNvbnRyYWN0LgogICAgcmVwdXRhdGlvbl9jbGllbnQucmVjb3JkX3RyYW5zYWN0aW9uKAogICAgICAgICZyZXB1dGF0aW9uX2FkbWluLAogICAgICAgICZlc2Nyb3dfaWQsCiAgICAgICAgJnQuc2VsbGVyLAogICAgICAgICZ0LmJ1eWVyLAogICAgICAgICZyZWxlYXNlZC5hbW91bnQsCiAgICAgICAgJlRyYW5zYWN0aW9uT3V0Y29tZTo6UmVsZWFzZWQsCiAgICApOwoKICAgIGxldCByZXB1dGF0aW9uID0gcmVwdXRhdGlvbl9jbGllbnQuZ2V0X3JlcHV0YXRpb24oJnQuc2VsbGVyKTsKICAgIGFzc2VydF9lcSEocmVwdXRhdGlvbi50b3RhbF90cmFuc2FjdGlvbnMsIDEpOwogICAgYXNzZXJ0X2VxIShyZXB1dGF0aW9uLnN1Y2Nlc3NmdWxfdHJhbnNhY3Rpb25zLCAxKTsKICAgIGFzc2VydF9lcSEocmVwdXRhdGlvbi5zY29yZSwgMTBfMDAwKTsKCiAgICAvLyBUaGUgYnV5ZXIsIGFzIGNvdW50ZXJwYXJ0eSwgbWF5IG5vdyByYXRlIHRoZSBzZWxsZXIgZm9yIHRoaXMgZXNjcm93LgogICAgcmVwdXRhdGlvbl9jbGllbnQucmF0ZV9lbnRpdHkoJnQuYnV5ZXIsICZlc2Nyb3dfaWQsICZ0LnNlbGxlciwgJjk1MDB1MzIpOwogICAgbGV0IGJyZWFrZG93biA9IHJlcHV0YXRpb25fY2xpZW50LmdldF9yZXB1dGF0aW9uX2JyZWFrZG93bigmdC5zZWxsZXIsICYwdTMyLCAmMTB1MzIpOwogICAgYXNzZXJ0X2VxIShicmVha2Rvd24uZ2V0KDApLnVud3JhcCgpLnJhdGluZywgU29tZSg5NTAwdTMyKSk7Cn0KCiNbdGVzdF0KZm4gdGVzdF9wZXJtaXNzaW9uX3Jldm9rZWRfYWZ0ZXJfc3BlbmRfYmVmb3JlX2VzY3Jvd19kZXBvc2l0X2ZhaWxzKCkgewogICAgbGV0IHQgPSBUZXN0RW52OjpzZXR1cCgpOwogICAgbGV0IHBlcm1fY2xpZW50ID0gUGVybWlzc2lvbnNDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQucGVybWlzc2lvbnNfY29udHJhY3RfaWQpOwogICAgbGV0IGVzY3Jvd19jbGllbnQgPSBFc2Nyb3dDb250cmFjdENsaWVudDo6bmV3KCZ0LmVudiwgJnQuZXNjcm93X2NvbnRyYWN0X2lkKTsKCiAgICAvLyBBcnJhbmdlOiBHcmFudCBwZXJtaXNzaW9uIHdpdGggc3VmZmljaWVudCBhbGxvd2FuY2UuCiAgICBsZXQgbGltaXRfdG90YWwgPSAxMDAwaTEyODsKICAgIGxldCBsaW1pdF9wZXJfdHggPSA1MDBpMTI4OwogICAgbGV0IHR0bF9sZWRnZXJzID0gMzYwMDB1MzI7CiAgICBsZXQgbWVyY2hhbnRzID0gVmVjOjo8QWRkcmVzcz46Om5ldygmdC5lbnYpOwoKICAgIHBlcm1fY2xpZW50LmdyYW50KAogICAgICAgICZ0LmJ1eWVyLAogICAgICAgICZ0LmFnZW50LAogICAgICAgICZsaW1pdF90b3RhbCwKICAgICAgICAmbGltaXRfcGVyX3R4LAogICAgICAgICZtZXJjaGFudHMsCiAgICAgICAgJnR0bF9sZWRnZXJzLAogICAgKTsKCiAgICAvLyBBY3QgMTogQWdlbnQgZXhlY3V0ZXMgc3BlbmQgd2l0aGluIGxpbWl0cy4KICAgIHBlcm1fY2xpZW50LmV4ZWN1dGVfc3BlbmQoJnQuYnV5ZXIsICZ0LmFnZW50LCAmMzAwLCAmdC5zZWxsZXIpOwogICAgbGV0IHBlcm1fcmVjb3JkID0gcGVybV9jbGllbnQuZ2V0X3Blcm1pc3Npb24oJnQuYnV5ZXIsICZ0LmFnZW50KTsKICAgIGFzc2VydF9lcSEocGVybV9yZWNvcmQuc3BlbnQsIDMwMCk7CgogICAgLy8gQWN0IDI6IE93bmVyIHJldm9rZXMgdGhlIHBlcm1pc3Npb24gYmVmb3JlIGVzY3JvdyBkZXBvc2l0LgogICAgcGVybV9jbGllbnQucmV2b2tlKCZ0LmJ1eWVyLCAmdC5hZ2VudCk7CgogICAgLy8gQXNzZXJ0OiBQZXJtaXNzaW9uIGlzIG5vIGxvbmdlciBhY3RpdmUgYW5kIHN1YnNlcXVlbnQgc3BlbmQvZGVwb3NpdCBmYWlscy4KICAgIGFzc2VydCEocGVybV9jbGllbnQuaXNfYWN0aXZlKCZ0LmJ1eWVyLCAmdC5hZ2VudCkpOwogICAgbGV0IHJldm9rZWRfcmVjb3JkID0gcGVybV9jbGllbnQuZ2V0X3Blcm1pc3Npb24oJnQuYnV5ZXIsICZ0LmFnZW50KTsKICAgIGFzc2VydF9lcSEocmV2b2tlZF9yZWNvcmQuc3RhdHVzLCBQZXJtaXNzaW9uU3RhdHVzOjpSZXZva2VkKTsKCiAgICBsZXQgc3BlbmRfcmVzdWx0ID0gcGVybV9jbGllbnQudHJ5X2V4ZWN1dGVfc3BlbmQoJnQuYnV5ZXIsICZ0LmFnZW50LCAmMjAwLCAmdC5zZWxsZXIpOwogICAgYXNzZXJ0X2VxIShzcGVuZF9yZXN1bHQsIEVycihPayhQZXJtaXNzaW9uRXJyb3I6OlVuYXV0aG9yaXplZCkpKTsKfQoKLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vLyBDcm9zcy1jb250cmFjdCBpbnRlZ3JhdGlvbiBiZW5jaG1hcmsgc3VpdGUKLy8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCi8vLwovLy8gU29yb2JhbiBlbmZvcmNlcyBhIHNpbmdsZS10cmFuc2FjdGlvbiBjZWlsaW5nIG9mIDUwMCwwMDAgQ1BVIGluc3RydWN0aW9ucwovLy8gYW5kIDEwMCBNQiBvZiBtZW1vcnkgKGFzIG9mIFByb3RvY29sIDIwKS4gVGhlIGFjY2VwdGFuY2UgY3JpdGVyaWEgZm9yIHRoaXMK Ly8vIGJlbmNobWFyayByZXF1aXJlIHRoZSBmdWxsIGUyZSBlc2Nyb3cgZmxvdyB0byBjb25zdW1lIGxlc3MgdGhhbiA1MCUKLy8vIG9mIHRoYXQgY2VpbGluZywgaS5lLiA8IDI1MCwwMDAgQ1BVIGluc3RydWN0aW9ucyBhbmQgPCA1MCBNQiBtZW1vcnkuCi8vLwovLy8gVGhlIGJlbmNobWFyayBpcyBleGVjdXRlZCBhcyBhIHNpbmdsZSB0ZXN0IGFuZCB0aGUgbWVhc3VyZWQgcmVzb3VyY2UKLy8vIGNvbnN1bXB0aW9uIGlzIHByaW50ZWQgdG8gc3RkZXJyIGluIGEgbWFjaGluZS1yZWFkYWJsZSBmb3JtYXQgc28gQ0kKLy8vIGNhbiB0cmFjayByZWdyZXNzaW9ucy4gVGhlIGFzc2VydGlvbnMgZmFpbCB0aGUgYnVpbGQgaWYgdGhlIGZsb3cgZXhjZWVkcwovLy8gdGhlIDUwJSBidWRnZXQuCi8vLyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQoKY29uc3QgU09ST0JBTl9UWF9DUFVfQ0VJTElORzogdTY0ID0gNTAwXzAwMDsKY29uc3QgU09ST0JBTl9UWF9NRU1fQ0VJTElORzogdTY0ID0gMTAwICogMTAyNCAqIDEwMjQ7CmNvbnN0IEJFTkNITUFSS19CVURHRVRfUEVSQ0VOVDogdTY0ID0gNTA7CgovLy8gUmVnaXN0ZXJzIGFsbCBmaXZlIGNvbnRyYWN0cyB1c2VkIGJ5IHRoZSBjb21tZXJjZSBmbG93IGFuZCByZXR1cm5zIHRoZQovLy8gY29tcGxldGUgY2xpZW50IGhhcm5lc3MuCmZuIGRlcGxveV9hbGxfY29udHJhY3RzKGVudjogJkVudikgLT4gKAogICAgQWRkcmVzcywgLy8gYWRtaW4KICAgIEFkZHJlc3MsIC8vIGJ1eWVyCiAgICBBZGRyZXNzLCAvLyBzZWxsZXIKICAgIEFkZHJlc3MsIC8vIGFnZW50CiAgICBBZGRyZXNzLCAvLyB0b2tlbiBjb250cmFjdCBpZAogICAgQWRkcmVzcywgLy8gZXNjcm93IGNvbnRyYWN0IGlkCiAgICBBZGRyZXNzLCAvLyBwZXJtaXNzaW9ucyBjb250cmFjdCBpZAogICAgQWRkcmVzcywgLy8gcmVwdXRhdGlvbiBjb250cmFjdCBpZAopIHsKICAgIGxldCBhZG1pbiA9IEFkZHJlc3M6OmdlbmVyYXRlKGVudik7CiAgICBsZXQgYnV5ZXIgPSBBZGRyZXNzOjpnZW5lcmF0ZShlbnYpOwogICAgbGV0IHNlbGxlciA9IEFkZHJlc3M6OmdlbmVyYXRlKGVudik7CiAgICBsZXQgYWdlbnQgPSBBZGRyZXNzOjpnZW5lcmF0ZShlbnYpOwogICAgbGV0IHRyZWFzdXJ5ID0gQWRkcmVzczo6Z2VuZXJhdGUoZW52KTsKCiAgICBsZXQgdG9rZW5fYWRtaW4gPSBBZGRyZXNzOjpnZW5lcmF0ZShlbnYpOwogICAgI1thbGxvd1tkZXByZWNhdGVkXV0KICAgIGxldCB0b2tlbl9jb250cmFjdF9pZCA9IGVudi5yZWdpc3Rlcl9zdGVsbGFyX2Fzc2V0X2NvbnRyYWN0KHRva2VuX2FkbWluLmNsb25lKCkpOwogICAgbGV0IHRva2VuX2FkbWluX2NsaWVudCA9CiAgICAgICAgc29yb2Jhbl9zZGs6OnRva2VuOjpTdGVsbGFyQXNzZXRDbGllbnQ6Om5ldyhlbnYsICZ0b2tlbl9jb250cmFjdF9pZCk7CiAgICB0b2tlbl9hZG1pbl9jbGllbnQubWludCgmYnV5ZXIsICZpbTEyODo6TUFYKTsKCiAgICBsZXQgZXNjcm93X2NvbmZpZyA9IEVzY3Jvd0NvbmZpZyB7CiAgICAgICAgYWRtaW46IGFkbWluLmNsb25lKCksCiAgICAgICAgZmVlX2JwczogMCwKICAgICAgICB0cmVhc3VyeSwKICAgICAgICBtaW5fYW1vdW50OiAxMDBpMTI4LAogICAgICAgIG1heF9hbW91bnQ6IDEwMDAwaTEyOCwKICAgIH07CiAgICBsZXQgZXNjcm93X2NvbnRyYWN0X2lkID0gZW52LnJlZ2lzdGVyKEVzY3Jvd0NvbnRyYWN0LCAoZXNjcm93X2NvbmZpZywpKTsKICAgIGxldCBwZXJtaXNzaW9uc19jb250cmFjdF9pZCA9IGVudi5yZWdpc3RlcihQZXJtaXNzaW9uc0NvbnRyYWN0LCAoKSk7CgogICAgbGV0IHJlcHV0YXRpb25fYWRtaW4gPSBBZGRyZXNzOjpnZW5lcmF0ZShlbnYpOwogICAgbGV0IHJlcHV0YXRpb25fY29udHJhY3RfaWQgPSBlbnYucmVnaXN0ZXIoCiAgICAgICAgUmVwdXRhdGlvbkNvbnRyYWN0LAogICAgICAgICgKICAgICAgICAgICAgcmVwdXRhdGlvbl9hZG1pbi5jbG9uZSgpLAogICAgICAgICAgICBSZXB1dGF0aW9uQ29uZmlnIHsKICAgICAgICAgICAgICAgIGRlY2F5X3dpbmRvd19zZWNvbmRzOiA5MCAqIDI0ICogNjAgKiA2MCwKICAgICAgICAgICAgICAgIG1pbl90cmFuc2FjdGlvbnNfdGhyZXNob2xkOiAxLAogICAgICAgICAgICAgICAgZGlzcHV0ZV9wZW5hbHR5X2JwczogNTAwLAogICAgICAgICAgICAgICAgZnJlZXplX3RocmVzaG9sZF9mbGFnczogMywKICAgICAgICAgICAgfSwKICAgICAgICApLAogICAgKTsKCiAgICBsZXQgZXNjcm93X2NsaWVudCA9IEVzY3Jvd0NvbnRyYWN0Q2xpZW50OjpuZXcoZW52LCAmZXNjcm93X2NvbnRyYWN0X2lkKTsKICAgIGVzY3Jvd19jbGllbnQuYWRkX3Rva2VuKCZhZG1pbiwgJnRva2VuX2NvbnRyYWN0X2lkKTsKCiAgICAoCiAgICAgICAgYWRtaW4sCiAgICAgICAgYnV5ZXIsCiAgICAgICAgc2VsbGVyLAogICAgICAgIGFnZW50LAogICAgICAgIHRva2VuX2NvbnRyYWN0X2lkLAogICAgICAgIGVzY3Jvd19jb250cmFjdF9pZCwKICAgICAgICBwZXJtaXNzaW9uc19jb250cmFjdF9pZCwKICAgICAgICByZXB1dGF0aW9uX2NvbnRyYWN0X2lkLAogICAgKQp9CgovLy8gUmVnaXN0ZXJzIGEgbWVyY2hhbnQgaW4gdGhlIG1hcmtldHBsYWNlIGNvbnRyYWN0IGFuZCByZXR1cm5zIHRoZSBtZXJjaGFudCBpZC4KZm4gcmVnaXN0ZXJfbWVyY2hhbnQoCiAgICBlbnY6ICZFbnYsCiAgICBtYXJrZXRwbGFjZV9jb250cmFjdF9pZDogJkFkZHJlc3MsCiAgICBzZWxsZXI6ICZBZGRyZXNzLAogICAgdG9rZW5fY29udHJhY3RfaWQ6ICZBZGRyZXNzLAopIC0+IHU2NCB7CiAgICBsZXQgbWFya2V0cGxhY2VfY2xpZW50ID0gTWFya2V0cGxhY2VDb250cmFjdENsaWVudDo6bmV3KGVudiwgbWFya2V0cGxhY2VfY29udHJhY3RfaWQpOwogICAgbWFya2V0cGxhY2VfY2xpZW50LnJlZ2lzdGVyX21lcmNoYW50KHNlbGxlciwgdG9rZW5fY29udHJhY3RfaWQpCn0KCi8vLyBSdW5zIHRoZSBmdWxsIGUyZSBlc2Nyb3cgY29tbWVyY2UgbG9vcCBhbmQgcmV0dXJucyB0aGUgbWVhc3VyZWQKLy8vIHJlc291cmNlIGNvbnN1bXB0aW9uIGZvciB0aGUgY29tcGxldGUgZmxvdy4KZm4gcnVuX2UyZV9jb21tZXJjZV9mbG93KGVudjogJkVudiAtPiAoKSB7CiAgICBlbnYubW9ja19hbGxfYXV0aHNfYWxsb3dpbmdfbm9uX3Jvb3RfYXV0aCgpOwoKICAgIGxldCAoCiAgICAgICAgX2FkbWluLAogICAgICAgIGJ1eWVyLAogICAgICAgIHNlbGxlciwKICAgICAgICBhZ2VudCwKICAgICAgICB0b2tlbl9jb250cmFjdF9pZCwKICAgICAgICBlc2Nyb3dfY29udHJhY3RfaWQsCiAgICAgICAgcGVybWlzc2lvbnNfY29udHJhY3RfaWQsCiAgICAgICAgcmVwdXRhdGlvbl9jb250cmFjdF9pZCwKICAgICkgPSBkZXBsb3lfYWxsX2NvbnRyYWN0cyhlbnYpOwoKICAgIC8vIFN0ZXAgMTogUmVnaXN0ZXIgbWVyY2hhbnQgaW4gdGhlIG1hcmtldHBsYWNlLgogICAgbGV0IG1hcmtldHBsYWNlX2NvbnRyYWN0X2lkID0gZW52LnJlZ2lzdGVyKE1hcmtldHBsYWNlQ29udHJhY3QsICgpKTsKICAgIGxldCBfbWVyY2hhbnRfaWQgPSByZWdpc3Rlcl9tZXJjaGFudCgKICAgICAgICBlbnYsCiAgICAgICAgJm1hcmtldHBsYWNlX2NvbnRyYWN0X2lkLAogICAgICAgICZzZWxsZXIsCiAgICAgICAgJnRva2VuX2NvbnRyYWN0X2lkLAogICAgKTsKCiAgICAvLyBTdGVwIDI6IEdyYW50IGRlbGVnYXRlZCBwZXJtaXNzaW9uIHRvIHRoZSBhZ2VudC4KICAgIGxldCBwZXJtX2NsaWVudCA9IFBlcm1pc3Npb25zQ29udHJhY3RDbGllbnQ6Om5ldyhlbnYsICZwZXJtaXNzaW9uc19jb250cmFjdF9pZCk7CiAgICBsZXQgbXV0IG1lcmNoYW50cyA9IFZlYzo6PEFkZHJlc3M+OjpuZXcoZW52KTsKICAgIG1lcmNoYW50cy5wdXNoX2JhY2soc2VsbGVyLmNsb25lKCkpOwogICAgcGVybV9jbGllbnQuZ3JhbnQoCiAgICAgICAgJmJ1eWVyLAogICAgICAgICZhZ2VudCwKICAgICAgICAmMTAwMGkxMjgsCiAgICAgICAgJjUwMGkxMjgsCiAgICAgICAgJm1lcmNoYW50cywKICAgICAgICAmMzYwMDB1MzIsCiAgICApOwoKICAgIC8vIFN0ZXAgMzogQ3JlYXRlIGVzY3JvdyB2aWEgZGVsZWdhdGVkIGRlcG9zaXQuCiAgICBsZXQgZXNjcm93X2NsaWVudCA9IEVzY3Jvd0NvbnRyYWN0Q2xpZW50OjpuZXcoZW52LCAmZXNjcm93X2NvbnRyYWN0X2lkKTsKICAgIHBlcm1fY2xpZW50LmV4ZWN1dGVfc3BlbmQoJmJ1eWVyLCAmYWdlbnQsICZhbW91bnQsICZzZWxsZXIpOwogICAgbGV0IGVzY3Jvd19pZCA9IGVzY3Jvd19jbGllbnQuZGVwb3NpdCgKICAgICAgICAmYnV5ZXIsCiAgICAgICAgJnNlbGxlciwKICAgICAgICAmdG9rZW5fY29udHJhY3RfaWQsCiAgICAgICAgJjQwMGkxMjgsCiAgICAgICAgJkJ5dGVzTjo6ZnJvbV9hcnJheShlbnYsICZbMXV1ODsgMzJdKSwKICAgICAgICAmMzYwMHUzMiwKICAgICAgICAmTm9uZSwKICAgICAgICAmTm9uZSwKICAgICk7CgogICAgLy8gU3RlcCA0OiBEZWxpdmVyIChyZWxlYXNlIGZyb20gZXNjcm93IHRvIHNlbGxlcikuCiAgICBlc2Nyb3dfY2xpZW50LnJlbGVhc2UoJmVzY3Jvd19pZCwgJmJ1eWVyLCAmc2VsbGVyKTsKCiAgICAvLyBTdGVwIDU6IFJlbGVhc2UgY29tcGxldGUgLSByZWNvcmQgb3V0Y29tZSBpbiByZXB1dGF0aW9uLgogICAgbGV0IHJlcHV0YXRpb25fY2xpZW50ID0gUmVwdXRhdGlvbkNvbnRyYWN0Q2xpZW50OjpuZXcoZW52LCAmcmVwdXRhdGlvbl9jb250cmFjdF9pZCk7CiAgICByZXB1dGF0aW9uX2NsaWVudC5yZWNvcmRfdHJhbnNhY3Rpb24oCiAgICAgICAgJmFkbWluLAogICAgICAgICZlc2Nyb3dfaWQsCiAgICAgICAgJnNlbGxlciwKICAgICAgICAmYnV5ZXIsCiAgICAgICAgJjQwMGkxMjgsCiAgICAgICAgJlRyYW5zYWN0aW9uT3V0Y29tZTo6UmVsZWFzZWQsCiAgICApOwp9CgojW3Rlc3RdCmZuIGJlbmNobWFya19mdWxsX2UyZV9jb21tZXJjZV9mbG93KCkgewogICAgbGV0IGVudiA9IEVudjo6ZGVmYXVsdCgpOwogICAgZW52Lm1vY2tfYWxsX2F1dGhzX2FsbG93aW5nX25vbl9yb290X2F1dGgoKTsKCiAgICAvLyBSdW4gdGhlIGZ1bGwgZmxvdyBvbmNlIHRvIGVuc3VyZSBjb3JyZWN0bmVzcy4KICAgIHJ1bl9lMmVfY29tbWVyY2VfZmxvdygmZW52KTsKCiAgICAvLyBNZWFzdXJlIHRoZSByZXNvdXJjZSBjb25zdW1wdGlvbiBvZiB0aGUgY29tcGxldGUgZmxvdy4KICAgIGxldCBidWRnZXQgPSBlbnYuYnVkZ2V0KCk7CiAgICBsZXQgY3B1X2luc3RydWN0aW9ucyA9IGJ1ZGdldC5jcHVfaW5zdHJ1Y3Rpb25zKCk7CiAgICBsZXQgbWVtb3J5X2J5dGVzID0gYnVkZ2V0Lm1lbW9yeV9ieXRlcygpOwoKICAgIC8vIEVtaXQgbWFjaGluZS1yZWFkYWJsZSBiZW5jaG1hcmsgb3V0cHV0IGZvciBDSSByZWdyZXNzaW9uIHRyYWNraW5nLgogICAgc3RkOjplcHJpbnRsbigKICAgICAgICAiQkVODQpNQVJLIGJlbmNobWFya19mdWxsX2UyZV9jb21tZXJjZV9mbG93IiwKICAgICk7CiAgICBzdGQ6OmVwcmludGxuKCJCRU5DSE1BUksgY3B1X2luc3RydWN0aW9ucz17fSIsIGNwdV9pbnN0cnVjdGlvbnMpOwogICAgc3RkOjplcHJpbnRsbigiQkVOQ0hNQVJLIG1lbW9yeV9ieXRlcz17fSIsIG1lbW9yeV9ieXRlcyk7CiAgICBzdGQ6OmVwcmludGxuKCJCRU5DSE1BUksgY3B1X2NlaWxpbmc9e30iLCBTT1JPQkFOX1RYX0NQVV9DRUlMSU5HKTsKICAgIHN0ZDo6ZXByaW50bG4oIkJFTkNITUFSSyBtZW1fY2VpbGluZz17fSIsIFNPUk9CQU5fVFhfTUVNX0NFSUxJTkcpOwogICAgc3RkOjplcHJpbnRsbigiQkVOQ0hNQVJLIGJ1ZGdldF9wZXJjZW50PXt9IiwgQkVOQ0hNQVJLX0JVREdFVF9QRVJDRU5UKTsKICAgIHN0ZDo6ZXByaW50bG4oIkVOREJFTkNIIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0iKTsKCiAgICAvLyBBc3NlcnQgdGhlIGZsb3cgc3RheXMgdW5kZXIgNTAlIG9mIHRoZSBTb3JvYmFuIHNpbmdsZS10cmFuc2FjdGlvbiBjZWlsaW5nLgogICAgbGV0IGNwdV9idWRnZXQgPSBTT1JPQkFOX1RYX0NQVV9DRUlMSU5HICogQkVOQ0hNQVJLX0JVREdFVF9QRVJDRU5UIC8gMTAwOwogICAgbGV0IG1lbV9idWRnZXQgPSBTT1JPQkFOX1RYX01FTV9DRUlMSU5HICogQkVOQ0hNQVJLX0JVREdFVF9QRVJDRU5UIC8gMTAwOwogICAgYXNzZXJ0ISgKICAgICAgICBjcHVfaW5zdHJ1Y3Rpb25zIDwgY3B1X2J1ZGdldCwKICAgICAgICAiZTJlIGZsb3cgZXhjZWVkZWQgNTAlIG9mIHRoZSBDUFUgY2VpbGluZzoge30gPj0ge30iLAogICAgICAgIGNwdV9pbnN0cnVjdGlvbnMsCiAgICAgICAgY3B1X2J1ZGdldAogICAgKTsKICAgIGFzc2VydCEoCiAgICAgICAgbWVtb3J5X2J5dGVzIDwgbWVtX2J1ZGdldCwKICAgICAgICAiZTJlIGZsb3cgZXhjZWVkZWQgNTAlIG9mIHRoZSBtZW1vcnkgY2VpbGluZzoge30gPj0ge30iLAogICAgICAgIG1lbW9yeV9ieXRlcywKICAgICAgICBtZW1fYnVkZ2V0CiAgICApOwp9Cg==
