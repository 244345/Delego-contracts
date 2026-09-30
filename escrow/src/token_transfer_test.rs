#![cfg(test)]

use soroban_sdk::{
    contract, contractimpl,
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    Address, Env,
};

use crate::{token_transfer::safe_token_transfer, EscrowError};

// --- Mock tokens -----------------------------------------------------------

#[contract]
pub struct VoidToken;
#[contractimpl]
impl VoidToken {
    pub fn transfer(_e: Env, _from: Address, _to: Address, _amount: i128) {}
}

#[contract]
pub struct BoolTrueToken;
#[contractimpl]
impl BoolTrueToken {
    pub fn transfer(_e: Env, _from: Address, _to: Address, _amount: i128) -> bool {
        true
    }
}

#[contract]
pub struct BoolFalseToken;
#[contractimpl]
impl BoolFalseToken {
    pub fn transfer(_e: Env, _from: Address, _to: Address, _amount: i128) -> bool {
        false
    }
}

#[contract]
pub struct PanicToken;
#[contractimpl]
impl PanicToken {
    pub fn transfer(_e: Env, _from: Address, _to: Address, _amount: i128) {
        panic!("insufficient balance");
    }
}

#[contract]
pub struct WeirdReturnToken;
#[contractimpl]
impl WeirdReturnToken {
    pub fn transfer(_e: Env, _from: Address, _to: Address, _amount: i128) -> u32 {
        1
    }
}

// Minimal host contract so `current_contract_address()` works.
#[contract]
pub struct Host;
#[contractimpl]
impl Host {}

fn run<T: soroban_sdk::testutils::Register>(token: T, amount: i128) -> Result<(), EscrowError> {
    let env = Env::default();
    env.mock_all_auths();
    let host = env.register(Host, ());
    let token_id = env.register(token, ());
    let to = Address::generate(&env);
    env.as_contract(&host, || safe_token_transfer(&env, &token_id, &to, amount))
}

// --- Tests -----------------------------------------------------------------

#[test]
fn void_return_is_ok() {
    assert_eq!(run(VoidToken, 100), Ok(()));
}

#[test]
fn bool_true_is_ok() {
    assert_eq!(run(BoolTrueToken, 100), Ok(()));
}

#[test]
fn bool_false_is_rejected() {
    assert_eq!(run(BoolFalseToken, 100), Err(EscrowError::TokenTransferRejected));
}

#[test]
fn trapping_token_maps_to_failed() {
    assert_eq!(run(PanicToken, 100), Err(EscrowError::TokenTransferFailed));
}

#[test]
fn unexpected_return_type_is_rejected() {
    assert_eq!(run(WeirdReturnToken, 100), Err(EscrowError::TokenUnexpectedReturn));
}

#[test]
fn non_positive_amount_is_rejected_before_calling_token() {
    assert_eq!(run(VoidToken, 0), Err(EscrowError::InvalidAmount));
    assert_eq!(run(VoidToken, -5), Err(EscrowError::InvalidAmount));
}

#[test]
fn works_with_real_stellar_asset_contract() {
    let env = Env::default();
    env.mock_all_auths();
    let host = env.register(Host, ());
    let admin = Address::generate(&env);
    let to = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin);
    let token_id = sac.address();

    StellarAssetClient::new(&env, &token_id).mint(&host, &1_000);

    let res = env.as_contract(&host, || safe_token_transfer(&env, &token_id, &to, 400));
    assert_eq!(res, Ok(()));

    let client = TokenClient::new(&env, &token_id);
    assert_eq!(client.balance(&to), 400);
    assert_eq!(client.balance(&host), 600);
}

#[test]
fn sac_insufficient_balance_maps_to_failed() {
    let env = Env::default();
    env.mock_all_auths();
    let host = env.register(Host, ());
    let admin = Address::generate(&env);
    let to = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract_v2(admin).address();

    StellarAssetClient::new(&env, &token_id).mint(&host, &50);

    let res = env.as_contract(&host, || safe_token_transfer(&env, &token_id, &to, 400));
    assert_eq!(res, Err(EscrowError::TokenTransferFailed));
}
