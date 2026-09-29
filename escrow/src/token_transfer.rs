//! Safe token transfer wrapper (issue #333).
//!
//! The Stellar Asset Contract (SAC) and SEP-41 tokens return `()` from
//! `transfer` and signal failure by trapping. Some custom Soroban tokens
//! instead return `bool` (ERC-20 style) and signal failure with `false`.
//! This wrapper calls `transfer` through `try_invoke_contract` with a raw
//! `Val` return type so both shapes are accepted, and everything else is
//! rejected instead of being silently treated as success.

use soroban_sdk::{
    symbol_short, vec, Address, Env, Error as SdkError, IntoVal, TryFromVal, Val, Vec,
};

use crate::EscrowError;

/// Transfer `amount` of `token` from the escrow contract to `to`.
///
/// Accepted outcomes:
/// - call succeeds and returns void (SAC / SEP-41)  -> `Ok(())`
/// - call succeeds and returns `true`                -> `Ok(())`
/// - call succeeds and returns `false`               -> `Err(TokenTransferRejected)`
/// - call succeeds and returns any other value       -> `Err(TokenUnexpectedReturn)`
/// - call traps / errors (insufficient balance etc.) -> `Err(TokenTransferFailed)`
pub fn safe_token_transfer(
    env: &Env,
    token: &Address,
    to: &Address,
    amount: i128,
) -> Result<(), EscrowError> {
    if amount <= 0 {
        return Err(EscrowError::InvalidAmount);
    }

    let from = env.current_contract_address();
    let args: Vec<Val> = vec![
        env,
        from.into_val(env),
        to.into_val(env),
        amount.into_val(env),
    ];

    match env.try_invoke_contract::<Val, SdkError>(token, &symbol_short!("transfer"), args) {
        Ok(Ok(ret)) => sanitize_return(env, ret),
        // Host-level failure or contract error/trap.
        _ => Err(EscrowError::TokenTransferFailed),
    }
}

fn sanitize_return(env: &Env, ret: Val) -> Result<(), EscrowError> {
    if ret.is_void() {
        return Ok(());
    }
    match bool::try_from_val(env, &ret) {
        Ok(true) => Ok(()),
        Ok(false) => Err(EscrowError::TokenTransferRejected),
        Err(_) => Err(EscrowError::TokenUnexpectedReturn),
    }
}
