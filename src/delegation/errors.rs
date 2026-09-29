use soroban_sdk::{contracterror, Env};

#[contracterror]
#[derive(Debug, Eq, PartialEq)]
pub enum PermissionError {
    #[msg("Permission denied")]
    PermissionDenied,

    #[msg("Signature epoch is stale")]
    StaleEpoch,

    #[msg("Invalid authorization signature")]
    InvalidSignature,
}