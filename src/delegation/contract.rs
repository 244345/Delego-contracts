use soroban_sdk::{contractimpl, Env, Symbol, Vec};
use soroban_sdk::token::{Token, TokenType};
use soroban_sdk::types::ContractData;

#[contractimpl]
pub struct DelegationContract;

#[contractimpl]
impl DelegationContract {
    pub fn pause_delegation(env: Env, delegation_id: Symbol) -> Result<(), PermissionError> {
        let mut state = Self::get_delegation_state(&env, delegation_id)?;
        state.increment_epoch(&env);
        state.is_paused = true;
        Self::set_delegation_state(&env, delegation_id, &state);
        Ok(())
    }

    pub fn resume_delegation(env: Env, delegation_id: Symbol) -> Result<(), PermissionError> {
        let mut state = Self::get_delegation_state(&env, delegation_id)?;
        state.increment_epoch(&env);
        state.is_paused = false;
        Self::set_delegation_state(&env, delegation_id, &state);
        Ok(())
    }

    pub fn execute_spend(
        env: Env,
        delegation_id: Symbol,
        auth: SpendAuthorization,
    ) -> Result<(), PermissionError> {
        let state = Self::get_delegation_state(&env, delegation_id)?;
        auth.validate_epoch(state.epoch_config.current_epoch)?;
        // ... existing spend logic
        Ok(())
    }
}