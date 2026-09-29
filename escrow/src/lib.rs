
      // Copyright 2024 Delego Labs
      // SPDX-License-Identifier: Apache-2.0
      use soroban_sdk::{contractimport, panic_with_error, Env, Symbol, Vec, Address};
      use soroban_sdk::token::TokenClient;

      #[derive(Debug, Clone, PartialEq, Eq)]
      pub enum EscrowError {
          MathOverflow,
          InvalidAmount,
          FeeTooHigh,
          InsufficientBalance,
      }

      /// Calculates fee with a minimum floor to prevent truncation evasion.
      /// Formula: `(amount * fee_bps) / 10_000` with `min_fee_stroops` as a hard floor.
      pub fn calculate_fee_with_minimum(
          env: &Env,
          amount: i128,
          fee_bps: u32,
          min_fee_stroops: i128,
      ) -> Result<i128, EscrowError> {
          // Prevent overflow by using checked operations
          let numerator = amount
              .checked_mul(fee_bps as i128)
              .ok_or(EscrowError::MathOverflow)?;

          let calculated = numerator
              .checked_div(10_000)
              .ok_or(EscrowError::MathOverflow)?;

          if amount > 0 && calculated < min_fee_stroops {
              Ok(min_fee_stroops.min(amount))
          } else {
              Ok(calculated)
          }
      }

      /// Validates that the calculated fee does not exceed the escrow amount.
      pub fn validate_fee(
          env: &Env,
          amount: i128,
          fee: i128,
      ) -> Result<(), EscrowError> {
          if fee > amount {
              return Err(EscrowError::FeeTooHigh);
          }
          Ok(())
      }
      