# Changelog

All notable changes to the Delego smart contracts are documented here, per
contract. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## How versions are tracked

Each contract's version mirrors the semver exposed by its on-chain `version()`
entry point, falling back to the crate version in `Cargo.toml` for contracts
that do not expose `version()` (e.g. `delegation_registry`).

[`.github/workflows/changelog.yml`](.github/workflows/changelog.yml) (via
[`scripts/check-changelog.sh`](scripts/check-changelog.sh)) fails CI when a
contract's declared version has no matching entry in this file. If you bump a
contract's version in code, record the bump here in the same PR — otherwise CI
will reject the change.

## escrow (delego-escrow)

### Unreleased

- Add dynamic platform fee tiering based on merchant settled volume (issue #328): admin-configured
  `FeeTier` ladder, per-merchant volume accumulation on every successful release, tier-aware fee
  computation on escrow release, and a `MerchantVolumeTierUpdatedEvent` emitted when a merchant
  reaches a higher volume bracket. Adds `set_fee_tiers`, `remove_fee_tier`, `get_fee_tiers`,
  `get_merchant_settled_volume`, `get_merchant_tier`, and `get_effective_fee_bps` entry points
  with `InvalidTier`/`TierLimitExceeded`/`TierNotFound` error codes.
- Fix pre-existing build breakage: declare the missing `EscrowError` variants used by the
  multi-sig upgrade and merchant-category validation paths, add the missing `DataKey::MerkleRoot`
  storage key, correct an `into_val` call in merchant-category validation, and skip the XDR spec
  export for `EscrowError` (the spec format caps error enums at 50 cases).
- Add immutable daily delivery Merkle roots and order-bound inclusion-proof escrow release.
- Add atomic batch escrow creation with per-token aggregate allowance transfers.
- Add admin split dispute settlements with buyer, seller, and mediator payouts.

### 0.2.0 - 2026-08-29

- Initial tracked release for this contract. On-chain `version()` returns `0.2.0`
  (escrow lifecycle: create/deposit/release/refund/dispute/cancel, receipts,
  timeouts, fee config, multi-admin).

## marketplace (delego-marketplace)

### Unreleased

### 0.2.0 - 2026-08-29

- Initial tracked release for this contract. On-chain `version()` returns `0.2.0`
  (merchant registry and discovery: registration, multi-verifier verification,
  category/name discovery, commission config, metadata cooldown, suspend/close,
  reputation score pairing).

## permissions (delego-permissions)

### Unreleased

### 0.1.0 - 2026-08-29

- Initial tracked release for this contract. On-chain `version()` returns `0.1.0`
  (delegated spending authority: grants, allowances, per-tx limits, relayed
  gasless spends, multi-owner grants, pause controls).

## reputation (delego-reputation)

### Unreleased

- Expose a fixed-point half-life decay helper that reduces stale scores toward zero.

### 0.0.1 - 2026-08-29

- Initial tracked release for this contract. `version()` mirrors the crate
  version (`0.0.1`): time-decayed reputation scores driven by transaction
  outcomes and ratings.

## delegation_registry (delego-delegation-registry)

### Unreleased

- Packed a delegation's four capabilities (spend, refund, dispute, delegate) into
  a single `u32` `PermissionBitmask` instead of storing them as individual
  booleans (issue #322). A delegation entry shrinks by ~72 B and reading or
  rewriting the capability set costs ~65% fewer CPU instructions, since the
  flags occupy one storage round-trip instead of four. `create_delegation`
  keeps its signature and still grants every capability; the new
  `create_scoped_delegation`, `set_permission_flag`, `clear_permission_flag`,
  `get_permissions`, `has_permission` and `is_authorized_for` entry points
  expose the scope. New `DelegationError::InvalidPermissionFlag` (315) rejects
  reserved and zero bits so a delegation can never carry capabilities the
  contract cannot interpret.

### 0.0.1 - 2026-08-29

- Initial tracked release for this contract. No on-chain `version()` entry point,
  so the crate version (`0.0.1`) is tracked here: delegation records with expiry
  and versioned rollback/upgrade support.
