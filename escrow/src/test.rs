#[cfg(test)]
#[allow(clippy::module_inception)]
mod test {
    use crate::{DataKey, EscrowContract, EscrowContractClient, EscrowError, EscrowMetadataEvent};
    use soroban_sdk::{
        symbol_short,
        testutils::{Address as _, Events, Ledger},
        Address, BytesN, Env, IntoVal, TryIntoVal,
    };

    fn setup_client(env: &Env) -> (EscrowContractClient<'_>, Address, Address) {
        let contract_id = env.register(EscrowContract, ());
        let client = EscrowContractClient::new(env, &contract_id);
        let admin = Address::generate(env);
        let treasury = Address::generate(env);
        client.initialize(&admin, &250u32, &treasury, &100i128, &1_000_000i128);
        (client, admin, contract_id)
    }

    const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const ZERO_CONTRACT_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn zero_account(env: &Env) -> Address {
        Address::from_str(env, ZERO_ACCOUNT_STRKEY)
    }

    fn zero_contract(env: &Env) -> Address {
        Address::from_str(env, ZERO_CONTRACT_STRKEY)
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register(EscrowContract, ());
        let client = EscrowContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let fee_bps = 250u32;
        let min_amount = 100i128;
        let max_amount = 10000i128;

        let res = client.initialize(&admin, &fee_bps, &treasury, &min_amount, &max_amount);
        assert!(res);

        let res_try = client.try_initialize(&admin, &fee_bps, &treasury, &min_amount, &max_amount);
        assert_eq!(res_try, Err(Ok(EscrowError::AlreadyInitialized)));
    }

    #[test]
    fn test_initialize_rejects_zero_treasury() {
        let env = Env::default();
        let contract_id = env.register(EscrowContract, ());
        let client = EscrowContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let treasury = zero_account(&env);

        let res = client.try_initialize(&admin, &250u32, &treasury, &100i128, &1_000_000i128);
        assert_eq!(res, Err(Ok(EscrowError::InvalidAddress)));
    }

    #[test]
    fn test_getters_return_errors_before_initialization() {
        let env = Env::default();
        let contract_id = env.register(EscrowContract, ());
        let client = EscrowContractClient::new(&env, &contract_id);

        assert_eq!(
            client.try_get_fee_config(),
            Err(Ok(EscrowError::FeeConfigNotSet))
        );
        assert_eq!(
            client.try_get_limits(),
            Err(Ok(EscrowError::AmountLimitsNotSet))
        );
        assert_eq!(client.try_get_admin(), Err(Ok(EscrowError::NotFound)));
    }

    #[test]
    fn test_get_admin_returns_initialized_admin() {
        let env = Env::default();
        let (client, admin, _contract_id) = setup_client(&env);

        let view = client.get_admin();

        assert_eq!(view.admin, admin);
        assert_eq!(view.pending_admin, None);
    }

    #[test]
    fn test_get_admin_includes_pending_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);
        let pending_admin = Address::generate(&env);

        assert!(client.propose_admin(&admin, &pending_admin));
        let view = client.get_admin();

        assert_eq!(view.admin, admin);
        assert_eq!(view.pending_admin, Some(pending_admin));
    }

    #[test]
    fn test_create_rejects_zero_addresses() {
        let env = Env::default();
        let (client, _admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token = zero_contract(&env);
        let order_id = BytesN::from_array(&env, &[1u8; 32]);

        let buyer_zero = client.try_create(
            &zero_account(&env),
            &seller,
            &token,
            &1000i128,
            &order_id,
            &100u32,
            &None,
            &None,
        );
        assert_eq!(buyer_zero, Err(Ok(EscrowError::InvalidAddress)));

        let seller_zero = client.try_create(
            &buyer,
            &zero_account(&env),
            &token,
            &1000i128,
            &order_id,
            &100u32,
            &None,
            &None,
        );
        assert_eq!(seller_zero, Err(Ok(EscrowError::InvalidAddress)));

        let token_zero = client.try_create(
            &buyer,
            &seller,
            &zero_contract(&env),
            &1000i128,
            &order_id,
            &100u32,
            &None,
            &None,
        );
        assert_eq!(token_zero, Err(Ok(EscrowError::InvalidAddress)));
    }

    #[test]
    fn test_create_rejects_same_buyer_and_seller() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let party = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[2u8; 32]);

        let res = client.try_create(
            &party, &party, &token, &1000i128, &order_id, &100u32, &None, &None,
        );
        assert_eq!(res, Err(Ok(EscrowError::InvalidEscrowParticipants)));
    }

    // ─── Issue #179: Storage Key Namespace Tests ───────────────────────────────

    #[test]
    fn test_storage_keys_are_distinct() {
        // DataKey variants must not collide so that Escrow(id), Admin, Config,
        // and metadata entries never overwrite each other in contract storage.
        let env = Env::default();

        let addr_a = Address::generate(&env);
        let addr_b = Address::generate(&env);

        let key_admin = DataKey::Admin.into_val(&env);
        let key_escrow_0: soroban_sdk::Val = DataKey::Escrow(0u64).into_val(&env);
        let key_escrow_1: soroban_sdk::Val = DataKey::Escrow(1u64).into_val(&env);
        let key_last_id: soroban_sdk::Val = DataKey::LastEscrowId.into_val(&env);
        let key_pending: soroban_sdk::Val = DataKey::PendingAdmin.into_val(&env);
        let key_admin_list: soroban_sdk::Val = DataKey::AdminList.into_val(&env);
        let key_fee: soroban_sdk::Val = DataKey::FeeConfig.into_val(&env);
        let key_limits: soroban_sdk::Val = DataKey::AmountLimits.into_val(&env);
        let key_quorum: soroban_sdk::Val = DataKey::QuorumConfig.into_val(&env);
        let key_votes_0: soroban_sdk::Val = DataKey::DisputeVotes(0u64).into_val(&env);
        let key_whitelist: soroban_sdk::Val = DataKey::TokenWhitelist.into_val(&env);
        let key_token_a: soroban_sdk::Val = DataKey::TokenEnabled(addr_a.clone()).into_val(&env);
        let key_token_b: soroban_sdk::Val = DataKey::TokenEnabled(addr_b.clone()).into_val(&env);
        let key_pause: soroban_sdk::Val = DataKey::PauseState.into_val(&env);
        let key_metadata_0: soroban_sdk::Val = DataKey::EscrowMetadata(0u64).into_val(&env);
        let key_metadata_1: soroban_sdk::Val = DataKey::EscrowMetadata(1u64).into_val(&env);
        let key_migration: soroban_sdk::Val = DataKey::MigrationFlag.into_val(&env);
        let key_fee_dist: soroban_sdk::Val = DataKey::FeeDistribution.into_val(&env);
        let key_require_cond_0: soroban_sdk::Val =
            DataKey::RequireReleaseCondition(0u64).into_val(&env);
        let key_require_cond_1: soroban_sdk::Val =
            DataKey::RequireReleaseCondition(1u64).into_val(&env);

        let all_keys: &[soroban_sdk::Val] = &[
            key_admin,
            key_escrow_0,
            key_escrow_1,
            key_last_id,
            key_pending,
            key_admin_list,
            key_fee,
            key_limits,
            key_quorum,
            key_votes_0,
            key_whitelist,
            key_token_a,
            key_token_b,
            key_pause,
            key_metadata_0,
            key_metadata_1,
            key_migration,
            key_fee_dist,
            key_require_cond_0,
            key_require_cond_1,
        ];

        // Assert every key is unique by comparing raw val representations
        for i in 0..all_keys.len() {
            for j in (i + 1)..all_keys.len() {
                let i_raw = soroban_sdk::Val::get_payload(all_keys[i]);
                let j_raw = soroban_sdk::Val::get_payload(all_keys[j]);
                assert_ne!(
                    i_raw, j_raw,
                    "DataKey collision detected at indices {i} and {j}"
                );
            }
        }
    }

    #[test]
    fn test_escrow_ids_produce_distinct_keys() {
        let env = Env::default();
        // Different escrow IDs must map to different storage keys.
        let k0: soroban_sdk::Val = DataKey::Escrow(0u64).into_val(&env);
        let k1: soroban_sdk::Val = DataKey::Escrow(1u64).into_val(&env);
        let k999: soroban_sdk::Val = DataKey::Escrow(999u64).into_val(&env);
        assert_ne!(
            soroban_sdk::Val::get_payload(k0),
            soroban_sdk::Val::get_payload(k1)
        );
        assert_ne!(
            soroban_sdk::Val::get_payload(k1),
            soroban_sdk::Val::get_payload(k999)
        );
    }

    #[test]
    fn test_token_enabled_keys_differ_per_address() {
        let env = Env::default();
        let addr_a = Address::generate(&env);
        let addr_b = Address::generate(&env);
        let ka: soroban_sdk::Val = DataKey::TokenEnabled(addr_a).into_val(&env);
        let kb: soroban_sdk::Val = DataKey::TokenEnabled(addr_b).into_val(&env);
        assert_ne!(
            soroban_sdk::Val::get_payload(ka),
            soroban_sdk::Val::get_payload(kb)
        );
    }

    #[test]
    fn test_metadata_keys_differ_per_escrow_id() {
        let env = Env::default();
        // Different escrow IDs must map to different metadata storage keys.
        let k0: soroban_sdk::Val = DataKey::EscrowMetadata(0u64).into_val(&env);
        let k1: soroban_sdk::Val = DataKey::EscrowMetadata(1u64).into_val(&env);
        let k999: soroban_sdk::Val = DataKey::EscrowMetadata(999u64).into_val(&env);
        assert_ne!(
            soroban_sdk::Val::get_payload(k0),
            soroban_sdk::Val::get_payload(k1)
        );
        assert_ne!(
            soroban_sdk::Val::get_payload(k1),
            soroban_sdk::Val::get_payload(k999)
        );
    }

    // ─── Issue #177 & #178: Admin Pause Flag + Event Tests ────────────────────

    #[test]
    fn test_set_create_paused_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        assert!(!client.get_create_paused());

        let res = client.set_create_paused(&admin, &true);
        assert!(res);
        assert!(client.get_create_paused());

        let res = client.set_create_paused(&admin, &false);
        assert!(res);
        assert!(!client.get_create_paused());
    }

    #[test]
    fn test_set_create_paused_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);
        let non_admin = Address::generate(&env);

        let res = client.try_set_create_paused(&non_admin, &true);
        assert_eq!(res, Err(Ok(EscrowError::Unauthorized)));
    }

    // ─── Issue #176: Token Getter Tests ───────────────────────────────────────

    #[test]
    fn test_get_token_not_found() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);

        let res = client.try_get_token(&999u64);
        assert_eq!(res, Err(Ok(EscrowError::NotFound)));
    }

    // ─── Issue #172: Escrow Creation Metadata Hash Tests ─────────────────────

    #[test]
    fn test_deposit_with_metadata_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[1u8; 32]);
        let order_hash = BytesN::from_array(&env, &[2u8; 32]);
        let schema = soroban_sdk::symbol_short!("order_v1");

        let escrow_id = client.deposit(
            &buyer,
            &seller,
            &token,
            &1000i128,
            &order_id,
            &100u32,
            &Some(order_hash.clone()),
            &Some(schema.clone()),
        );

        // Verify metadata was stored
        let metadata = client.get_escrow_metadata(&escrow_id);
        assert_eq!(metadata.order_hash, order_hash);
        assert_eq!(metadata.schema, schema);
    }

    #[test]
    fn test_deposit_without_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[1u8; 32]);

        // Deposit without metadata (None for both parameters)
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        // Verify metadata is not found
        let res = client.try_get_escrow_metadata(&escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::NotFound)));
    }

    #[test]
    fn test_deposit_with_partial_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[1u8; 32]);
        let order_hash = BytesN::from_array(&env, &[2u8; 32]);

        // Deposit with only order_hash (schema is None)
        let escrow_id = client.deposit(
            &buyer,
            &seller,
            &token,
            &1000i128,
            &order_id,
            &100u32,
            &Some(order_hash),
            &None,
        );

        // Verify metadata is not stored when only one parameter is provided
        let res = client.try_get_escrow_metadata(&escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::NotFound)));
    }

    #[test]
    fn test_get_escrow_metadata_not_found() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);

        // Try to get metadata for non-existent escrow
        let res = client.try_get_escrow_metadata(&999u64);
        assert_eq!(res, Err(Ok(EscrowError::NotFound)));
    }

    // ─── Issue #175: Escrow Metadata Event Tests ─────────────────────────────

    #[test]
    fn test_deposit_with_metadata_emits_metadata_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[1u8; 32]);
        let order_hash = BytesN::from_array(&env, &[2u8; 32]);
        let schema = symbol_short!("order_v1");

        client.deposit(
            &buyer,
            &seller,
            &token,
            &1000i128,
            &order_id,
            &100u32,
            &Some(order_hash.clone()),
            &Some(schema.clone()),
        );

        let events = env.events().all();
        let mut found = false;
        for event in events.iter() {
            let (contract, topics, value) = event;
            if contract != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("metadata") {
                let evt: EscrowMetadataEvent = value.try_into_val(&env).unwrap();
                assert_eq!(evt.escrow_id, order_id);
                assert_eq!(evt.order_hash, order_hash);
                assert_eq!(evt.schema, schema);
                found = true;
            }
        }
        assert!(found, "EscrowMetadataEvent not found in events");
    }

    #[test]
    fn test_deposit_without_metadata_does_not_emit_metadata_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[1u8; 32]);

        client.deposit(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        for event in env.events().all().iter() {
            let (contract, topics, _value) = event;
            if contract != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            assert!(
                !(t0 == symbol_short!("escrow") && t1 == symbol_short!("metadata")),
                "EscrowMetadataEvent must not be emitted when metadata is absent"
            );
        }
    }

    #[test]
    fn test_deposit_with_partial_metadata_does_not_emit_metadata_event() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[1u8; 32]);
        let order_hash = BytesN::from_array(&env, &[2u8; 32]);

        client.deposit(
            &buyer,
            &seller,
            &token,
            &1000i128,
            &order_id,
            &100u32,
            &Some(order_hash),
            &None,
        );

        for event in env.events().all().iter() {
            let (contract, topics, _value) = event;
            if contract != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            assert!(
                !(t0 == symbol_short!("escrow") && t1 == symbol_short!("metadata")),
                "EscrowMetadataEvent must not be emitted for partial metadata"
            );
        }
    }

    // ─── Merchant Escrow Cancellation Tests ──────────────────────────────────

    #[test]
    fn test_merchant_cancel_created_escrow_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[7u8; 32]);
        let reason = symbol_short!("out_stock");

        let escrow_id = client.create(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        let record = client.get_escrow(&escrow_id);
        assert_eq!(record.status, crate::EscrowStatus::Created);

        let cancelled = client.cancel(&escrow_id, &seller, &reason);
        assert!(cancelled);

        // Verify EscrowCancelledEvent emission (retrieve events right after contract call)
        let events = env.events().all();

        let updated_record = client.get_escrow(&escrow_id);
        assert_eq!(updated_record.status, crate::EscrowStatus::Cancelled);

        let mut found = false;
        for event in events.iter() {
            let (c_id, topics, value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("cancelled") {
                let evt: crate::EscrowCancelledEvent = value.try_into_val(&env).unwrap();
                assert_eq!(evt.escrow_id, order_id);
                assert_eq!(evt.cancelled_by, seller);
                assert_eq!(evt.reason, reason);
                found = true;
            }
        }
        assert!(found, "EscrowCancelledEvent was not emitted");
    }

    #[test]
    fn test_cancel_unauthorized_caller_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let random_caller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[8u8; 32]);
        let reason = symbol_short!("no_stock");

        let escrow_id = client.create(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        let res = client.try_cancel(&escrow_id, &random_caller, &reason);
        assert_eq!(res, Err(Ok(EscrowError::Unauthorized)));
    }

    #[test]
    fn test_cancel_after_funded_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[9u8; 32]);
        let reason = symbol_short!("too_late");

        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        let record = client.get_escrow(&escrow_id);
        assert_eq!(record.status, crate::EscrowStatus::Funded);

        let res = client.try_cancel(&escrow_id, &seller, &reason);
        assert_eq!(res, Err(Ok(EscrowError::AlreadyFunded)));
    }

    #[test]
    fn test_cancel_already_cancelled_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[10u8; 32]);
        let reason = symbol_short!("duplicate");

        let escrow_id = client.create(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        client.cancel(&escrow_id, &seller, &reason);

        let res = client.try_cancel(&escrow_id, &seller, &reason);
        assert_eq!(res, Err(Ok(EscrowError::AlreadyCancelled)));
    }

    #[test]
    fn test_funding_cancelled_escrow_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[11u8; 32]);
        let reason = symbol_short!("cancelled");

        let escrow_id = client.create(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        client.cancel(&escrow_id, &seller, &reason);

        let res = client.try_fund(&escrow_id, &buyer);
        assert_eq!(res, Err(Ok(EscrowError::AlreadyCancelled)));
    }

    // ─── Issue #325: Upgrade Path + Version Check Tests ───────────────────────

    // A minimal Soroban contract (a single `ping` function, no storage) compiled
    // for wasm32-unknown-unknown. The host requires a valid contract WASM (with
    // the standard contract metadata section) to accept an `upload_contract_wasm`
    // call, so a bare/empty module is not sufficient here. This stub's exported
    // functions are never invoked — it only serves as the upgrade target so
    // `upgrade` has a real contract-code ledger entry to point at.
    const WASM_STUB: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x60, 0x00, 0x01, 0x7e,
        0x60, 0x00, 0x00, 0x03, 0x03, 0x02, 0x00, 0x01, 0x05, 0x03, 0x01, 0x00, 0x10, 0x06, 0x09,
        0x01, 0x7f, 0x01, 0x41, 0x80, 0x80, 0xc0, 0x00, 0x0b, 0x07, 0x15, 0x03, 0x06, 0x6d, 0x65,
        0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x01, 0x5f,
        0x00, 0x01, 0x0a, 0x09, 0x02, 0x04, 0x00, 0x42, 0x01, 0x0b, 0x02, 0x00, 0x0b, 0x00, 0x2b,
        0x0e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x73, 0x70, 0x65, 0x63, 0x76, 0x30,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x70, 0x69, 0x6e,
        0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1e,
        0x11, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x65, 0x6e, 0x76, 0x6d, 0x65, 0x74,
        0x61, 0x76, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x6f, 0x0e, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x6d, 0x65, 0x74, 0x61,
        0x76, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x72, 0x73, 0x76, 0x65, 0x72,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x31, 0x2e, 0x39, 0x37, 0x2e, 0x31, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x72, 0x73, 0x73, 0x64, 0x6b, 0x76, 0x65,
        0x72, 0x00, 0x00, 0x00, 0x30, 0x32, 0x32, 0x2e, 0x30, 0x2e, 0x31, 0x31, 0x23, 0x33, 0x34,
        0x66, 0x37, 0x66, 0x35, 0x33, 0x61, 0x65, 0x33, 0x31, 0x65, 0x30, 0x66, 0x64, 0x30, 0x32,
        0x61, 0x61, 0x62, 0x34, 0x33, 0x36, 0x61, 0x39, 0x38, 0x37, 0x32, 0x65, 0x37, 0x39, 0x66,
        0x61, 0x36, 0x37, 0x31, 0x63, 0x61, 0x30, 0x32,
    ];

    #[test]
    fn test_check_version_returns_current_version() {
        let env = Env::default();
        let (client, _admin, _contract_id) = setup_client(&env);

        let v = client.check_version();
        assert_eq!(v.name, symbol_short!("escrow"));
        assert_eq!(v.semver, symbol_short!("0_2_0"));
        assert_eq!(v, client.version());
    }

    #[test]
    fn test_upgrade_requires_admin_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);

        let not_admin = Address::generate(&env);
        // Auth is checked before the wasm hash is ever used, so a dummy hash suffices.
        let wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

        let res = client.try_upgrade(&not_admin, &wasm_hash);
        assert_eq!(res, Err(Ok(EscrowError::Unauthorized)));
        assert!(!client.is_migrated());
    }

    #[test]
    fn test_upgrade_with_admin_auth_preserves_escrow_data() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[3u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );
        let record_before = client.get_escrow(&escrow_id);
        assert!(!client.is_migrated());

        let wasm_hash = env.deployer().upload_contract_wasm(WASM_STUB);
        let upgraded = client.upgrade(&admin, &wasm_hash);
        assert!(upgraded);

        // The contract's executable now points at the stub wasm, so we read
        // storage directly rather than going through the client (whose calls
        // would now be dispatched to the stub, which implements nothing).
        let migrated: bool = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&crate::DataKey::MigrationFlag)
                .unwrap_or(false)
        });
        assert!(migrated, "migration flag must be set after upgrade");

        let record_after: crate::EscrowRecord = env.as_contract(&contract_id, || {
            env.storage()
                .persistent()
                .get(&crate::DataKey::Escrow(escrow_id))
                .unwrap()
        });
        assert_eq!(
            record_before, record_after,
            "escrow data must survive the code upgrade"
        );
    }

    // ─── Issue #327: Multi-Treasury Fee Distribution Tests ────────────────────

    #[test]
    fn test_fee_distribution_split_across_treasuries() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let treasury_a = Address::generate(&env);
        let treasury_b = Address::generate(&env);
        let mut shares = soroban_sdk::Vec::new(&env);
        shares.push_back(crate::TreasuryShare {
            treasury: treasury_a.clone(),
            bps: 300,
        });
        shares.push_back(crate::TreasuryShare {
            treasury: treasury_b.clone(),
            bps: 200,
        });
        client.set_fee_distribution(&admin, &shares);

        let order_id = BytesN::from_array(&env, &[9u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        client.dispute(&escrow_id, &buyer);
        client.resolve_dispute(&escrow_id, &admin, &true);

        // 3% of 1000 = 30, 2% of 1000 = 20; seller receives the remaining 950.
        assert_eq!(token_client.balance(&treasury_a), 30);
        assert_eq!(token_client.balance(&treasury_b), 20);
        assert_eq!(token_client.balance(&seller), 950);
    }

    #[test]
    fn test_set_fee_distribution_rejects_over_1000_bps() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let treasury_a = Address::generate(&env);
        let treasury_b = Address::generate(&env);
        let mut shares = soroban_sdk::Vec::new(&env);
        shares.push_back(crate::TreasuryShare {
            treasury: treasury_a,
            bps: 600,
        });
        shares.push_back(crate::TreasuryShare {
            treasury: treasury_b,
            bps: 500,
        });

        let res = client.try_set_fee_distribution(&admin, &shares);
        assert_eq!(res, Err(Ok(EscrowError::InvalidFeeBps)));
        assert_eq!(client.get_fee_distribution().len(), 0);
    }

    #[test]
    fn test_fee_uses_single_treasury_when_no_distribution_configured() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);
        let treasury = client.get_fee_config().treasury;

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_admin_client.mint(&buyer, &10000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[10u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1000i128, &order_id, &100u32, &None, &None,
        );

        client.dispute(&escrow_id, &buyer);
        client.resolve_dispute(&escrow_id, &admin, &true);

        // fee_bps = 250 (2.5%) from setup_client -> fee = 25
        assert_eq!(token_client.balance(&treasury), 25);
        assert_eq!(token_client.balance(&seller), 975);
    }

    // ─── Issue #319: Time-Locked Emergency Pause Tests ──────────────────────────

    #[test]
    fn test_emergency_pause_auto_expires() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        assert!(!client.get_create_paused());

        // Set emergency pause for 10 ledgers
        let res = client.set_emergency_pause(&admin, &true, &10u32);
        assert!(res);
        assert!(client.get_create_paused());

        // Advance 9 ledgers - still paused
        env.ledger().with_mut(|li| {
            li.sequence_number = 9;
        });
        assert!(client.get_create_paused());

        // Advance to expiry - should auto-unpause
        env.ledger().with_mut(|li| {
            li.sequence_number = 10;
        });
        assert!(!client.get_create_paused());
    }

    #[test]
    fn test_manual_unpause_before_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        // Set emergency pause for 100 ledgers
        client.set_emergency_pause(&admin, &true, &100u32);
        assert!(client.get_create_paused());

        // Manually unpause before expiry
        client.set_create_paused(&admin, &false);
        assert!(!client.get_create_paused());
    }

    #[test]
    fn test_get_create_paused_respects_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        // Set emergency pause for 5 ledgers
        client.set_emergency_pause(&admin, &true, &5u32);

        // Before expiry - paused
        env.ledger().with_mut(|li| {
            li.sequence_number = 4;
        });
        assert!(client.get_create_paused());

        // After expiry - unpaused
        env.ledger().with_mut(|li| {
            li.sequence_number = 5;
        });
        assert!(!client.get_create_paused());
    }

    #[test]
    fn test_emergency_pause_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);
        let non_admin = Address::generate(&env);

        let res = client.try_set_emergency_pause(&non_admin, &true, &10u32);
        assert_eq!(res, Err(Ok(EscrowError::Unauthorized)));
    }

    #[test]
    fn test_set_emergency_pause_zero_duration_is_permanent() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        // Set emergency pause with 0 duration (permanent)
        client.set_emergency_pause(&admin, &true, &0u32);
        assert!(client.get_create_paused());

        // Advance many ledgers - still paused
        env.ledger().with_mut(|li| {
            li.sequence_number = 1000;
        });
        assert!(client.get_create_paused());
    }

    // ── Ticket 1: clear_release_condition ────────────────────────────────────

    /// Create a funded escrow with a release condition set, return the escrow id.
    fn setup_escrow_with_condition(
        env: &Env,
        client: &EscrowContractClient<'_>,
        admin: &Address,
    ) -> u64 {
        let buyer = Address::generate(env);
        let seller = Address::generate(env);
        let token_admin = Address::generate(env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(admin, &token);

        let order_id = BytesN::from_array(env, &[42u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        // Register a dummy oracle contract so the address is valid.
        let oracle_id = env.register(EscrowContract, ());
        let condition_type = symbol_short!("delivery");
        client.set_release_condition(admin, &escrow_id, &condition_type, &oracle_id);
        escrow_id
    }

    #[test]
    fn test_clear_release_condition_admin_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let escrow_id = setup_escrow_with_condition(&env, &client, &admin);

        // Condition must exist before clearing.
        let cond = client.get_release_condition(&escrow_id);
        assert_eq!(cond.condition_type, symbol_short!("delivery"));

        // Admin clears it — must succeed.
        client.clear_release_condition(&admin, &escrow_id);

        // Now get_release_condition should return the NotSet error.
        let res = client.try_get_release_condition(&escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::ReleaseConditionNotSet)));
    }

    #[test]
    fn test_clear_release_condition_co_admin_success() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let co_admin = Address::generate(&env);
        client.add_co_admin(&admin, &co_admin);

        let escrow_id = setup_escrow_with_condition(&env, &client, &admin);

        // Co-admin should also be authorized.
        client.clear_release_condition(&co_admin, &escrow_id);

        let res = client.try_get_release_condition(&escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::ReleaseConditionNotSet)));
    }

    #[test]
    fn test_clear_release_condition_non_admin_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let escrow_id = setup_escrow_with_condition(&env, &client, &admin);
        let non_admin = Address::generate(&env);

        let res = client.try_clear_release_condition(&non_admin, &escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::Unauthorized)));
    }

    #[test]
    fn test_clear_release_condition_on_released_escrow_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[43u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        // Release it fully so status = Released.
        client.release(&escrow_id, &buyer, &seller);

        let res = client.try_clear_release_condition(&admin, &escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::AlreadyReleased)));
    }

    #[test]
    fn test_get_release_condition_returns_none_after_clear() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let escrow_id = setup_escrow_with_condition(&env, &client, &admin);
        client.clear_release_condition(&admin, &escrow_id);

        // Confirming via try variant that the storage key is gone.
        let res = client.try_get_release_condition(&escrow_id);
        assert_eq!(res, Err(Ok(EscrowError::ReleaseConditionNotSet)));
    }

    // ── Ticket 2: get_yield_config ────────────────────────────────────────────

    #[test]
    fn test_get_yield_config_returns_none_when_unset() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[50u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let result = client.get_yield_config(&escrow_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_yield_config_returns_some_after_set() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[51u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let lending_contract = Address::generate(&env);
        let apr_bps = 500u32; // 5% APR
        client.set_yield_config(&admin, &escrow_id, &lending_contract, &apr_bps);

        let result = client.get_yield_config(&escrow_id);
        assert!(result.is_some());
        let cfg = result.unwrap();
        assert_eq!(cfg.lending_contract, lending_contract);
        assert_eq!(cfg.apr_bps, apr_bps);
    }

    // ── Ticket 3: get_co_admins / get_pending_admin ───────────────────────────

    #[test]
    fn test_get_co_admins_returns_empty_vec_when_none_added() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);

        let co_admins = client.get_co_admins();
        assert_eq!(co_admins.len(), 0);
    }

    #[test]
    fn test_get_co_admins_returns_populated_list_after_add() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let co_admin_a = Address::generate(&env);
        let co_admin_b = Address::generate(&env);
        client.add_co_admin(&admin, &co_admin_a);
        client.add_co_admin(&admin, &co_admin_b);

        let co_admins = client.get_co_admins();
        assert_eq!(co_admins.len(), 2);
        assert!(co_admins.contains(&co_admin_a));
        assert!(co_admins.contains(&co_admin_b));
    }

    #[test]
    fn test_get_pending_admin_returns_none_when_no_transfer() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);

        let result = client.get_pending_admin();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_pending_admin_returns_some_after_propose() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let new_admin = Address::generate(&env);
        client.propose_admin(&admin, &new_admin);

        let result = client.get_pending_admin();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), new_admin);
    }

    // ─── Issue #32: DisputeVotedEvent Tests ─────────────────────────────────

    /// Helper: set up an escrow in Disputed state with quorum config.
    /// Returns (client, contract_id, escrow_id, arbiters).
    fn setup_disputed_escrow(
        env: &Env,
        threshold: u32,
    ) -> (
        EscrowContractClient<'_>,
        Address,
        u64,
        soroban_sdk::Vec<Address>,
    ) {
        env.mock_all_auths();
        let (client, admin, contract_id) = setup_client(env);

        let buyer = Address::generate(env);
        let seller = Address::generate(env);
        let token_admin = Address::generate(env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        // Create 3 arbiters for quorum.
        let arbiter_a = Address::generate(env);
        let arbiter_b = Address::generate(env);
        let arbiter_c = Address::generate(env);
        let mut arbiters = soroban_sdk::Vec::new(env);
        arbiters.push_back(arbiter_a);
        arbiters.push_back(arbiter_b);
        arbiters.push_back(arbiter_c);
        client.set_quorum_config(&admin, &arbiters, &threshold);

        let order_id = BytesN::from_array(env, &[11u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &100u32, &None, &None,
        );

        client.dispute(&escrow_id, &buyer);

        (client, contract_id, escrow_id, arbiters)
    }

    /// Emit DisputeVotedEvent under (escrow, "vote") after each vote mutation,
    /// with live votes_for/threshold.
    #[test]
    fn test_vote_dispute_emits_dispute_voted_event() {
        let env = Env::default();
        let (client, contract_id, escrow_id, arbiters) = setup_disputed_escrow(&env, 2); // threshold = 2
        let arbiter = arbiters.get(0).unwrap();

        client.vote_dispute(&escrow_id, &arbiter, &true);

        let events = env.events().all();
        let mut found = false;
        for event in events.iter() {
            let (c_id, topics, value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("vote") {
                let evt: crate::DisputeVotedEvent = value.try_into_val(&env).unwrap();
                assert_eq!(evt.escrow_id, escrow_id);
                assert_eq!(evt.arbiter, arbiter);
                assert!(evt.release_to_seller);
                assert_eq!(evt.votes_for, 1); // first vote for seller side
                assert_eq!(evt.threshold, 2);
                found = true;
            }
        }
        assert!(found, "DisputeVotedEvent not found in events");
    }

    /// After a vote for buyer (release_to_seller = false), votes_for must stay 0.
    #[test]
    fn test_vote_dispute_emits_zero_votes_for_on_buyer_vote() {
        let env = Env::default();
        let (client, contract_id, escrow_id, arbiters) = setup_disputed_escrow(&env, 2);
        let arbiter = arbiters.get(0).unwrap();

        client.vote_dispute(&escrow_id, &arbiter, &false); // vote for buyer

        let events = env.events().all();
        let mut found = false;
        for event in events.iter() {
            let (c_id, topics, value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("vote") {
                let evt: crate::DisputeVotedEvent = value.try_into_val(&env).unwrap();
                assert_eq!(evt.escrow_id, escrow_id);
                assert_eq!(evt.arbiter, arbiter);
                assert!(!evt.release_to_seller);
                assert_eq!(evt.votes_for, 0); // no votes for seller side
                assert_eq!(evt.threshold, 2);
                found = true;
            }
        }
        assert!(found, "DisputeVotedEvent not found in events");
    }

    /// Quorum boundary: second seller-side vote should show votes_for = threshold.
    #[test]
    fn test_vote_dispute_quorum_boundary_emits_correct_tally() {
        let env = Env::default();
        let (client, contract_id, escrow_id, arbiters) = setup_disputed_escrow(&env, 2); // threshold = 2

        // First seller vote.
        client.vote_dispute(&escrow_id, &arbiters.get(0).unwrap(), &true);

        // Second seller vote — reaches quorum.
        client.vote_dispute(&escrow_id, &arbiters.get(1).unwrap(), &true);

        // Find the LAST DisputeVotedEvent — it should show votes_for = 2.
        let events = env.events().all();
        let mut last_evt: Option<crate::DisputeVotedEvent> = None;
        for event in events.iter() {
            let (c_id, topics, value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("vote") {
                last_evt = Some(value.try_into_val(&env).unwrap());
            }
        }
        let evt = last_evt.expect("DisputeVotedEvent not found in events");
        assert_eq!(evt.escrow_id, escrow_id);
        assert_eq!(evt.arbiter, arbiters.get(1).unwrap());
        assert!(evt.release_to_seller);
        assert_eq!(evt.votes_for, 2); // quorum reached
        assert_eq!(evt.threshold, 2);
    }

    /// Each vote emits exactly one event (no duplicates, no missing).
    #[test]
    fn test_vote_dispute_emits_exactly_one_event_per_vote() {
        let env = Env::default();
        let (client, contract_id, escrow_id, arbiters) = setup_disputed_escrow(&env, 3); // threshold = 3

        // Vote 1: verify exactly one DisputeVotedEvent.
        client.vote_dispute(&escrow_id, &arbiters.get(0).unwrap(), &true);
        let mut count = 0u32;
        for event in env.events().all().iter() {
            let (c_id, topics, _value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("vote") {
                count += 1;
            }
        }
        assert_eq!(
            count, 1,
            "first vote should emit exactly one DisputeVotedEvent"
        );

        // Vote 2: verify exactly one more DisputeVotedEvent.
        client.vote_dispute(&escrow_id, &arbiters.get(1).unwrap(), &true);
        count = 0;
        for event in env.events().all().iter() {
            let (c_id, topics, _value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("vote") {
                count += 1;
            }
        }
        assert_eq!(
            count, 1,
            "second vote should emit exactly one DisputeVotedEvent"
        );

        // Vote 3: verify exactly one more.
        client.vote_dispute(&escrow_id, &arbiters.get(2).unwrap(), &false);
        count = 0;
        for event in env.events().all().iter() {
            let (c_id, topics, _value) = event;
            if c_id != contract_id || topics.len() != 2 {
                continue;
            }
            let t0: soroban_sdk::Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            let t1: soroban_sdk::Symbol = topics.get(1).unwrap().try_into_val(&env).unwrap();
            if t0 == symbol_short!("escrow") && t1 == symbol_short!("vote") {
                count += 1;
            }
        }
        assert_eq!(
            count, 1,
            "third vote should emit exactly one DisputeVotedEvent"
        );
    }

    // ─── Issue #34: Monotonic YieldView Tests ────────────────────────────────

    #[test]
    fn test_get_accrued_yield_returns_yield_view() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[60u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let lending = Address::generate(&env);
        let apr_bps = 500u32; // 5% APR
        client.set_yield_config(&admin, &escrow_id, &lending, &apr_bps);

        let view = client.get_accrued_yield(&escrow_id);
        assert_eq!(view.escrow_id, escrow_id);
        assert_eq!(view.principal, 1_000i128);
        assert_eq!(view.apy_bps, 500);
        assert_eq!(view.snapshot_ledger, env.ledger().sequence());
        // accrued may be 0 at ledger 0 since created_at == timestamp
        assert!(view.accrued >= 0);
    }

    #[test]
    fn test_get_accrued_yield_not_found() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin, _contract_id) = setup_client(&env);

        let res = client.try_get_accrued_yield(&999u64);
        assert_eq!(res, Err(Ok(EscrowError::NotFound)));
    }

    #[test]
    fn test_get_accrued_yield_no_config_returns_zero() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[61u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );
        // No yield config set.

        let view = client.get_accrued_yield(&escrow_id);
        assert_eq!(view.escrow_id, escrow_id);
        assert_eq!(view.principal, 1_000i128);
        assert_eq!(view.apy_bps, 0);
        assert_eq!(view.held_seconds, 0);
        assert_eq!(view.accrued, 0);
    }

    /// Same-block reads must be identical.
    #[test]
    fn test_get_accrued_yield_same_block_reads_identical() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[62u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let lending = Address::generate(&env);
        client.set_yield_config(&admin, &escrow_id, &lending, &500u32);

        // Two reads within the same ledger must be identical.
        let view_a = client.get_accrued_yield(&escrow_id);
        let view_b = client.get_accrued_yield(&escrow_id);

        assert_eq!(view_a, view_b, "same-block reads must be identical");
        assert_eq!(view_a.snapshot_ledger, view_b.snapshot_ledger);
        assert_eq!(view_a.held_seconds, view_b.held_seconds);
        assert_eq!(view_a.accrued, view_b.accrued);
    }

    /// Cross-block reads must be monotonically non-decreasing.
    #[test]
    fn test_get_accrued_yield_cross_block_monotonic() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[63u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let lending = Address::generate(&env);
        client.set_yield_config(&admin, &escrow_id, &lending, &500u32);

        let view_before = client.get_accrued_yield(&escrow_id);

        // Advance 100 ledgers.
        env.ledger().with_mut(|li| {
            li.sequence_number = li.sequence_number + 100;
        });

        let view_after = client.get_accrued_yield(&escrow_id);

        assert!(
            view_after.held_seconds >= view_before.held_seconds,
            "held_seconds must be monotonically non-decreasing"
        );
        assert!(
            view_after.accrued >= view_before.accrued,
            "accrued yield must be monotonically non-decreasing"
        );
        assert!(
            view_after.snapshot_ledger > view_before.snapshot_ledger,
            "snapshot_ledger must advance"
        );
    }

    // ─── Issue #33: Partial-release yield test ────────────────────────────────

    /// After a partial release, yield must be computed on the remaining
    /// principal, not the original amount.
    #[test]
    fn test_get_accrued_yield_scales_by_remaining_principal() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[70u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let lending = Address::generate(&env);
        client.set_yield_config(&admin, &escrow_id, &lending, &1_000u32); // 10% APR

        // Advance 1 year so yield is non-trivial.
        env.ledger().with_mut(|li| {
            li.sequence_number = 1000;
            li.timestamp = 31_536_000; // ~1 year in seconds
        });

        // Before partial release: yield on full 1000 principal.
        let before = client.get_accrued_yield(&escrow_id);
        assert_eq!(before.principal, 1_000i128);
        assert!(before.accrued > 0, "yield should be non-zero");

        // Partial release: 500 of 1000.
        client.partial_release(&escrow_id, &buyer, &500);

        // After partial release: yield must be computed on remaining 500.
        let after = client.get_accrued_yield(&escrow_id);
        assert_eq!(after.principal, 500i128);
        // accrued should be roughly half of before (same time, half principal).
        assert!(
            after.accrued < before.accrued,
            "yield after partial release must be less than before ({} < {})",
            after.accrued,
            before.accrued
        );
        assert!(
            after.accrued > 0,
            "yield should still be non-zero after partial release"
        );
    }

    // ─── Issue #35: updated_at lifecycle tests ──────────────────────────────

    /// updated_at must be set to the ledger timestamp on creation.
    #[test]
    fn test_updated_at_set_on_creation() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[80u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let record = client.get_escrow(&escrow_id);
        assert_eq!(record.updated_at, record.created_at);
    }

    /// updated_at must advance when escrow status changes (fund → dispute).
    #[test]
    fn test_updated_at_advances_on_dispute() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[81u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let after_deposit = client.get_escrow(&escrow_id);
        assert_eq!(after_deposit.updated_at, after_deposit.created_at);

        // Advance ledger and dispute.
        env.ledger().with_mut(|li| {
            li.sequence_number = 50;
        });

        client.dispute(&escrow_id, &buyer);

        let after_dispute = client.get_escrow(&escrow_id);
        assert!(
            after_dispute.updated_at >= after_deposit.updated_at,
            "updated_at must advance after dispute"
        );
    }

    /// updated_at must advance across a full lifecycle: deposit → dispute → resolve.
    #[test]
    fn test_updated_at_advances_full_lifecycle() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin, _contract_id) = setup_client(&env);

        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        let token_admin = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin)
            .address();
        let token_admin_client = soroban_sdk::token::StellarAssetClient::new(&env, &token);
        token_admin_client.mint(&buyer, &10_000i128);
        client.add_token(&admin, &token);

        let order_id = BytesN::from_array(&env, &[82u8; 32]);
        let escrow_id = client.deposit(
            &buyer, &seller, &token, &1_000i128, &order_id, &1_000u32, &None, &None,
        );

        let r1 = client.get_escrow(&escrow_id);

        env.ledger().with_mut(|li| {
            li.sequence_number = 50;
        });
        client.dispute(&escrow_id, &buyer);
        let r2 = client.get_escrow(&escrow_id);
        assert!(r2.updated_at >= r1.updated_at);

        env.ledger().with_mut(|li| {
            li.sequence_number = 100;
        });
        client.resolve_dispute(&escrow_id, &admin, &true);
        let r3 = client.get_escrow(&escrow_id);
        assert!(
            r3.updated_at >= r2.updated_at,
            "updated_at must advance through resolve"
        );
    }

    // ====================================================================
    // Property tests for escrow fee math (Issue #130)
    // ====================================================================
    //
    // These tests verify the fee calculation used by `split_release`:
    //   fee = (amount / 10_000) * fee_bps + ((amount % 10_000) * fee_bps) / 10_000
    //
    // This is mathematically equivalent to:
    //   floor(amount × fee_bps / 10_000)
    //
    // Constraints:
    //   - fee_bps is u32, validated <= 1000 at initialization
    //   - amount is i128, validated > 0 in split_release
    // ====================================================================

    /// Independent oracle: compute floor(amount × fee_bps / 10_000)
    /// using wider arithmetic (i128 × i128 → i256 via u128) to avoid
    /// any overflow in the test itself.
    fn oracle_fee(amount: i128, fee_bps: i128) -> i128 {
        // Use u128 for intermediate calculation to avoid overflow.
        // amount is positive (validated by contract), fee_bps <= 1000.
        // Max product: 2^127 × 1000, which fits in u128.
        let a = amount as u128;
        let b = fee_bps as u128;
        ((a * b) / 10_000u128) as i128
    }

    /// Reproduce the production fee formula exactly as implemented
    /// in `split_release`.
    fn production_fee(amount: i128, fee_bps: i128) -> i128 {
        (amount / 10_000i128) * fee_bps + ((amount % 10_000i128) * fee_bps) / 10_000i128
    }

    const MAX_VALID_FEE_BPS: i128 = 1000;

    // ---- FEE PROPERTY 1: FLOOR ACCURACY ----
    // For broad valid inputs, the production formula matches the
    // independent floor oracle.
    #[test]
    fn property_fee_floor_accuracy() {
        let fee_bps_values: &[i128] = &[0, 1, 10, 50, 100, 250, 500, 999, 1000];

        for &bps in fee_bps_values {
            // Sweep amounts from 0 to 200_000 in steps
            let mut amount = 0i128;
            while amount <= 200_000 {
                let actual = production_fee(amount, bps);
                let expected = oracle_fee(amount, bps);
                assert_eq!(
                    actual, expected,
                    "floor accuracy: fee({}, {}) = {}, expected {}",
                    amount, bps, actual, expected
                );
                amount += 1;
            }
        }
    }

    // ---- FEE PROPERTY 2: BOUNDS ----
    // fee >= 0 and fee <= amount for valid inputs.
    #[test]
    fn property_fee_bounds() {
        let fee_bps_values: &[i128] = &[0, 1, 100, 250, 500, 1000];
        let amounts: &[i128] = &[
            0,
            1,
            2,
            5,
            10,
            99,
            100,
            999,
            1000,
            10_000,
            10_001,
            100_000,
            1_000_000,
            i128::MAX / 2,
        ];

        for &bps in fee_bps_values {
            for &amt in amounts {
                let fee = production_fee(amt, bps);
                assert!(
                    fee >= 0,
                    "fee must be non-negative: fee({}, {}) = {}",
                    amt,
                    bps,
                    fee
                );
                assert!(
                    fee <= amt,
                    "fee must not exceed amount: fee({}, {}) = {}",
                    amt,
                    bps,
                    fee
                );
            }
        }
    }

    // ---- FEE PROPERTY 3: DUST ----
    // Test amounts 0..10_000 where rounding matters most.
    #[test]
    fn property_fee_dust() {
        let bps_values: &[i128] = &[1, 10, 100, 250, 500, 1000];

        for &bps in bps_values {
            for amt in 0i128..10_000 {
                let fee = production_fee(amt, bps);
                let expected = oracle_fee(amt, bps);
                assert_eq!(
                    fee, expected,
                    "dust: fee({}, {}) = {}, expected {}",
                    amt, bps, fee, expected
                );
            }
        }
    }

    // ---- FEE PROPERTY 4: ZERO BPS ----
    // fee(amount, 0) == 0 for all amounts.
    #[test]
    fn property_fee_zero_bps() {
        let amounts: &[i128] = &[0, 1, 100, 10_000, 100_000, i128::MAX / 2];

        for &amt in amounts {
            let fee = production_fee(amt, 0);
            assert_eq!(fee, 0, "zero bps: fee({}, 0) = {}, expected 0", amt, fee);
        }
    }

    // ---- FEE PROPERTY 5: MAXIMUM VALID BPS ----
    // fee(amount, 1000) == amount / 10 for all amounts.
    // (1000 / 10_000 = 10%, so fee = floor(amount / 10))
    #[test]
    fn property_fee_max_bps() {
        let amounts: &[i128] = &[
            0,
            1,
            2,
            9,
            10,
            11,
            99,
            100,
            999,
            1000,
            10_000,
            10_001,
            100_000,
            1_000_000,
            i128::MAX / 2,
        ];

        for &amt in amounts {
            let fee = production_fee(amt, MAX_VALID_FEE_BPS);
            let expected = amt / 10;
            assert_eq!(
                fee, expected,
                "max bps: fee({}, 1000) = {}, expected {}",
                amt, fee, expected
            );
        }
    }

    // ---- FEE PROPERTY 6: ROUNDING BOUNDARIES ----
    // Test amounts where amount × bps is just below/above a multiple
    // of 10_000.
    #[test]
    fn property_fee_rounding_boundaries() {
        let bps_values: &[i128] = &[1, 3, 7, 100, 250, 333, 500, 777, 1000];

        for &bps in bps_values {
            // Test amounts around multiples of 10_000 / gcd(10_000, bps)
            for multiple in 1..=20i128 {
                let base = multiple * 10_000 / bps;
                // Test base - 1, base, base + 1
                for offset in -1i128..=1i128 {
                    let amt = (base + offset).max(0);
                    let fee = production_fee(amt, bps);
                    let expected = oracle_fee(amt, bps);
                    assert_eq!(
                        fee, expected,
                        "rounding: fee({}, {}) = {}, expected {}",
                        amt, bps, fee, expected
                    );
                }
            }
        }
    }

    // ---- FEE PROPERTY 7: MONOTONICITY ----
    // For fixed valid BPS: amount1 <= amount2 => fee(amount1) <= fee(amount2)
    // For fixed amount: bps1 <= bps2 => fee(amount, bps1) <= fee(amount, bps2)
    #[test]
    fn property_fee_monotonicity_amount() {
        let bps_values: &[i128] = &[1, 10, 100, 250, 500, 1000];
        let amounts: &[i128] = &[
            0, 1, 2, 5, 10, 50, 100, 500, 1000, 5000, 10_000, 10_001, 50_000, 100_000, 1_000_000,
        ];

        for &bps in bps_values {
            let mut prev_fee = i128::MIN;
            for &amt in amounts {
                let fee = production_fee(amt, bps);
                assert!(
                    fee >= prev_fee,
                    "amount monotonicity violated: fee({}, {})={} < fee({}, {})={}",
                    amt,
                    bps,
                    fee,
                    amounts[amounts.iter().position(|&a| a == prev_fee).unwrap_or(0)],
                    bps,
                    prev_fee
                );
                prev_fee = fee;
            }
        }
    }

    #[test]
    fn property_fee_monotonicity_bps() {
        let amounts: &[i128] = &[0, 1, 100, 1000, 10_000, 100_000];
        let bps_values: &[i128] = &[0, 1, 10, 50, 100, 250, 500, 750, 999, 1000];

        for &amt in amounts {
            let mut prev_fee = i128::MIN;
            for &bps in bps_values {
                let fee = production_fee(amt, bps);
                assert!(
                    fee >= prev_fee,
                    "bps monotonicity violated: fee({}, {})={} < fee({}, {})={}",
                    amt,
                    bps,
                    fee,
                    amt,
                    bps_values[bps_values.iter().position(|&b| b == prev_fee).unwrap_or(0)],
                    prev_fee
                );
                prev_fee = fee;
            }
        }
    }

    // ---- FEE PROPERTY 8: PRODUCTION-ORACLE AGREEMENT ----
    // For a broad sweep of (amount, fee_bps) pairs, verify the
    // production formula matches the independent oracle.
    #[test]
    fn property_fee_matches_oracle() {
        let bps_values: &[i128] = &[0, 1, 2, 5, 10, 25, 50, 100, 250, 500, 750, 999, 1000];

        for &bps in bps_values {
            // Sweep amounts in powers of 10 and around key boundaries.
            // Duplicates are harmless and keep the code no_std friendly.
            let amounts: &[i128] = &[
                0,
                1,
                4,
                5,
                6,
                9,
                10,
                11,
                49,
                50,
                51,
                99,
                100,
                101,
                499,
                500,
                501,
                999,
                1000,
                1001,
                4999,
                5000,
                5001,
                9999,
                10_000,
                10_001,
                49_999,
                50_000,
                50_001,
                99_999,
                100_000,
                100_001,
                499_999,
                500_000,
                500_001,
                999_999,
                1_000_000,
                1_000_001,
                4_999_999,
                5_000_000,
                5_000_001,
                9_999_999,
                10_000_000,
                10_000_001,
                49_999_999,
                50_000_000,
                50_000_001,
                99_999_999,
                100_000_000,
                100_000_001,
                499_999_999,
                500_000_000,
                500_000_001,
                999_999_999,
                1_000_000_000,
                1_000_000_001,
                4_999_999_999,
                5_000_000_000,
                5_000_000_001,
                9_999_999_999,
                10_000_000_000,
                10_000_000_001,
                49_999_999_999,
                50_000_000_000,
                50_000_000_001,
                99_999_999_999,
                100_000_000_000,
                100_000_000_001,
                499_999_999_999,
                500_000_000_000,
                500_000_000_001,
                999_999_999_999,
                1_000_000_000_000,
            ];

            for &amt in amounts {
                let actual = production_fee(amt, bps);
                let expected = oracle_fee(amt, bps);
                assert_eq!(
                    actual, expected,
                    "oracle agreement: fee({}, {}) = {}, expected {}",
                    amt, bps, actual, expected
                );
            }
        }
    }

    // ---- FEE PROPERTY 9: ZERO AMOUNT ----
    // fee(0, bps) == 0 for all valid BPS values.
    #[test]
    fn property_fee_zero_amount() {
        let bps_values: &[i128] = &[0, 1, 100, 250, 500, 1000];

        for &bps in bps_values {
            let fee = production_fee(0, bps);
            assert_eq!(fee, 0, "zero amount: fee(0, {}) = {}, expected 0", bps, fee);
        }
    }
}
