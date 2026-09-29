# Permissions Contract

On-chain spending controls for delegated AI agent authority.

Grants allow an owner to delegate spending authority to another address
("delegate") with optional limits, expiry, and per-transaction caps. The
contract supports multi-owner grants, relayer (gasless) spends, allowances,
pause/resume, and permission transfers.

## Functions

| Function | Auth required | Description |
|---|---|---|
| `grant` | owner | Grant spending permission to a delegate |
| `grant_child` | owner | Grant a nested permission derived from an existing grant |
| `revoke` | owner | Revoke a delegate's permission |
| `transfer_permission` | owner | Transfer a permission to another account |
| `renew_permission` | owner | Extend the expiry of a grant |
| `update_expiry` | owner | Change a grant's expiry ledger |
| `can_spend` | — | Check whether a spend is allowed (limits + expiry) |
| `execute_spend` | delegate | Spend within the grant limits; emits `PermissionSpendEvent` |
| `set_relayer_key` / `get_relayer_key` | delegate | Configure the key used for relayer-signed spends |
| `execute_spend_via_relayer` | relayer signature | Gasless spend using a relayer signature + nonce |
| `grant_multi_owner` | owners | Multi-owner grant (quorum-based authorization) |
| `can_spend_multi` / `execute_spend_multi` | owners | Quorum checks and spend for multi-owner grants |
| `get_multi_permission` / `preview_spend` | — | Read-only grant and spend previews |
| `get_permission` / `get_remaining_allowance` / `get_allowance_detail` | — | Read-only allowance and grant views |
| `increase_allowance` / `decrease_allowance` | owner | Adjust a grant's allowance |
| `pause` / `resume` | owner | Pause/resume a delegate's permission |
| `get_pause_metadata` | — | Pause state and reason |
| `set_admin` / `propose_admin` / `accept_admin` | admin | Admin management (two-step transfer) |
| `pause_grants` | admin | Pause all new grants |
| `sweep_expired` / `sweep_expired_batch` | any | Sweep expired permissions into Expired status (single or bounded batch) |
| `sweep_inactive` / `sweep_inactive_batch` | any | Auto-revoke inactive permissions idle past threshold (single or bounded batch) |
| `get_audit_log_page` | — | Read up to 20 retained audit entries using a zero-based cursor |
| `recheck_merchant_verification` | — | Dynamic check whether a merchant meets the current verification policy |
| `revalidate_merchant_status` | any | Re-evaluate a merchant against the current policy, applying the grace period |

## Events

Events are emitted with the topic prefix `("perm", …)`:

| Second topic | Payload struct | Emitted by |
|---|---|---|
| `"granted"` | `PermissionGrantedEvent` | `grant` / `grant_child` / `grant_multi_owner` (`"mgrant"`) |
| `"merc_list"` | — | Grant with merchant allow/deny lists |
| `"revoked"` | `PermissionRevokedEvent` | `revoke` |
| `"transf"` | `PermissionTransferredEvent` | `transfer_permission` |
| `"renewed"` / `"exp_upd"` | — | `renew_permission` / `update_expiry` |
| `"spent"` / `"mspent"` / `"relayed"` | `PermissionSpendEvent` | `execute_spend` / `execute_spend_multi` / `execute_spend_via_relayer` |
| `"allowinc"` / `"allowdec"` | — | `increase_allowance` / `decrease_allowance` |
| `"paused"` / `"resumed"` / `"gpaused"` | `PermissionPausedEvent` / `PermissionResumedEvent` | `pause` / `resume` / `pause_grants` |
| `"vpolicy"` | `VerificationPolicyUpdatedEvent` | Policy update capturing the grace period |
| `"vrevalid"` | `VerificationRevalidatedEvent` | `revalidate_merchant_status` |

## Verification Policy Threshold Increases

Merchant verification is evaluated dynamically against the current
policy rather than a cached boolean flag. When governance raises the
required attestation count (e.g. from 1 to 2), merchants verified under the
previous policy are not immediately de-verified. Instead they receive a
30-day grace period (counted in ledgers) to acquire the additional
attestations.

- `recheck_merchant_verification` is the pure dynamic check. It returns
true only when the merchant's attestation count meets or exceeds the
current policy's `required` threshold.
- `revalidate_merchant_status` is the on-chain entrypoint. It re-evaluates
the merchant against the current policy and applies the grace period to
pre-existing merchants. Merchants that fail to meet the updated standard
transition gracefully to a `Suspended` status once the grace period has
elapsed.

## Development

```bash
cd permissions

# Run all tests
cargo test

# Build WASM for deployment
cargo build --target wasm32-unknown-unknown --release
```

> TypeScript types mirroring the on-chain records (e.g. the `PermissionGrant`
> interface) ship in [`@delegolabs/types`](https://github.com/DelegoLabs/Delego-backend),
> published from the Delego-backend repository.

Audit entries are stored under individual indexed persistent keys in a
10-entry ring buffer. `get_audit_log_page(owner, delegate, cursor)` returns
`AuditTrailPage`; follow `next_cursor` until it is `None`. Queries deserialize
at most 20 entries rather than the full trail.
