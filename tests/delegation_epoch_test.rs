use soroban_sdk::{test::Ledger, Env, Symbol};
use soroban_sdk::token::{Token, TokenType};
use soroban_sdk::types::ContractData;

#[test]
fn test_epoch_increment_on_pause_resume() {
    let env = Env::default();
    let client = DelegationContractClient::new(&env, &DelegationContract);

    let delegation_id = Symbol::from_utf8(&env, "test_delegation").unwrap();
    let owner = Address::generate(&env);
    let agent = Address::generate(&env);

    // Initial state
    let initial_state = client.get_delegation_state(&delegation_id);
    assert_eq!(initial_state.epoch_config.current_epoch, 0);

    // Pause increments epoch
    client.pause_delegation(&delegation_id);
    let paused_state = client.get_delegation_state(&delegation_id);
    assert_eq!(paused_state.epoch_config.current_epoch, 1);

    // Resume increments epoch again
    client.resume_delegation(&delegation_id);
    let resumed_state = client.get_delegation_state(&delegation_id);
    assert_eq!(resumed_state.epoch_config.current_epoch, 2);
}

#[test]
fn test_stale_signature_rejection() {
    let env = Env::default();
    let client = DelegationContractClient::new(&env, &DelegationContract);

    let delegation_id = Symbol::from_utf8(&env, "test_delegation").unwrap();
    let owner = Address::generate(&env);
    let agent = Address::generate(&env);

    // Create auth with epoch 0
    let auth = SpendAuthorization {
        delegator: owner,
        agent,
        amount: 100,
        recipient: Address::generate(&env),
        nonce: 0,
        epoch: 0,
        signature: vec![0u8; 64],
    };

    // Pause/resume to advance epoch
    client.pause_delegation(&delegation_id);
    client.resume_delegation(&delegation_id);

    // Should fail with StaleEpoch
    let result = client.execute_spend(&delegation_id, auth);
    assert!(matches!(result, Err(PermissionError::StaleEpoch)));
}