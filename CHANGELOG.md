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

### 0.0.1 - 2026-08-29

- Initial tracked release for this contract. `version()` mirrors the crate
  version (`0.0.1`): time-decayed reputation scores driven by transaction
  outcomes and ratings.

## delegation_registry (delego-delegation-registry)

### Unreleased

### 0.0.1 - 2026-08-29

- Initial tracked release for this contract. No on-chain `version()` entry point,
  so the crate version (`0.0.1`) is tracked here: delegation records with expiry
  and versioned rollback/upgrade support.
