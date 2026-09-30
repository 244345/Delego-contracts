
      // Copyright 2024 Delego Labs
      // SPDX-License-Identifier: Apache-2.0
      use soroban_sdk::{testutils::Address as _, Env, Symbol};
      use soroban_sdk::token::TokenClient;
      use super::*;

      #[test]
      fn test_min_fee_enforcement() {
          let env = Env::default();
          let min_fee = 100; // 100 Stroops minimum

          // Micro-transaction under 10,000 Stroops should pay min_fee
          assert_eq!(
              calculate_fee_with_minimum(&env, 5_000, 100, min_fee).unwrap(),
              min_fee
          );

          // Transaction under min_fee should still pay min_fee
          assert_eq!(
              calculate_fee_with_minimum(&env, 1, 100, min_fee).unwrap(),
              min_fee
          );

          // Normal transaction should calculate normally
          assert_eq!(
              calculate_fee_with_minimum(&env, 10_000, 100, min_fee).unwrap(),
              100
          );

          // Zero amount should return zero
          assert_eq!(
              calculate_fee_with_minimum(&env, 0, 100, min_fee).unwrap(),
              0
          );
      }

      #[test]
      fn test_overflow_safety() {
          let env = Env::default();
          let min_fee = 100;

          // Test i128 overflow (amount * fee_bps exceeds i128 max)
          let max_amount = i128::MAX / 10_000;
          let max_fee_bps = u32::MAX as i128;

          assert!(calculate_fee_with_minimum(&env, max_amount, max_fee_bps as u32, min_fee).is_err());
      }
      