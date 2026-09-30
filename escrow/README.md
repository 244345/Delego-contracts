# Escrow Contract

Soroban smart contract for holding purchase funds until fulfillment.

## Functions

| Function | Auth required | Description |
|---|---|---|
| `initialize` | — | Set admin, fee config, and amount limits |
| `version` | — | Return contract name and semver |
| `create` | — | Create an unfunded escrow record in `Created` status |
| `fund` | buyer | Fund an existing `Created` escrow |
| `cancel` | seller (merchant) | Cancel an unfunded `Created` escrow (guarded, see below) |
| `accept_order` | seller (merchant) | Record acceptance of an order and re-anchor its cancel window |
| `agree_cancel` | buyer | Waive the cancel protection window for one escrow |
| `get_order_acceptance` | — | Acceptance and cancel-protection snapshot for an escrow |
| `get_cancel_eligibility` | — | Whether a seller may cancel an escrow right now, and why |
| `get_cancel_lockout` | — | Configured default cancel protection window, in ledgers |
| `set_cancel_lockout` | admin | Set the default cancel protection window for new escrows |
| `deposit` | buyer | Lock buyer funds for an order (convenience `create` + `fund`) |
| `batch_create_escrows` | buyer | Atomically create and fund up to 50 orders with aggregated token allowances |
| `release` | buyer / admin | Transfer full remaining balance to seller |
| `publish_merkle_root` | admin / co-admin | Anchor an immutable daily delivery Merkle root |
| `release_with_merkle_proof` | buyer | Release funds after proving delivery inclusion |
| `verify_merkle_proof` | — | Verify a SHA-256 Merkle path |
| `partial_release` | buyer / admin | Transfer a partial amount to seller |
| `refund` | seller / admin / buyer (after timeout) | Return funds to buyer |
| `dispute` | buyer / seller | Mark escrow as disputed |
| `resolve_dispute` | admin | Resolve dispute, release to seller or refund buyer |
| `resolve_dispute_split` | admin | Resolve a dispute with buyer, seller, and mediator payouts |
| `resolve_dispute_quorum` | any (after quorum) | Resolve via multi-arbiter quorum vote |
| `vote_dispute` | arbiter | Cast a quorum vote on a disputed escrow |
| `get_escrow` | — | Full `EscrowRecord` for an escrow id |
| `get_receipt` | — | Compact buyer-facing receipt |
| `get_merchant_receipt` | — | Seller-facing receipt with `release_eligible` flag |
| `get_release_eligibility` | — | Whether a release can proceed and why |
| `get_refund_eligibility` | — | Whether a caller can refund and why |
| `get_timeout_view` | — | Timeout metadata: ledger numbers and refundability |
| `get_escrow_metadata` | — | Optional off-chain order hash stored at deposit |
| `get_token` | — | Token address for an escrow |
| `get_fee_config` | — | Current fee config |
| `get_limits` | — | Current amount limits |
| `get_quorum_config` | — | Current arbiter quorum config |
| `get_dispute_votes` | — | Votes cast on a disputed escrow |
| `get_create_paused` | — | Whether new escrow creation is paused |
| `verify_delivery_and_release` | caller | Verify an Ed25519 delivery proof and release funds |
| `get_admin` | — | Current primary admin and pending transfer target |
| `set_limits` | admin | Update amount limits |
| `set_quorum_config` | admin | Update arbiter list and threshold |
| `update_fee` | admin | Update fee basis points |
| `add_token` | admin | Whitelist a token for deposits |
| `remove_token` | admin | Remove a token from the whitelist |
| `list_tokens` | — | List all whitelisted tokens |
| `is_token_allowed` | — | Check if a token is whitelisted |
| `set_create_paused` | admin | Pause or unpause new escrow creation |
| `set_merchant_registry` | admin | Configure marketplace checks for seller trading status |
| `set_oracle_public_key` | admin | Configure the Ed25519 key accepted for delivery proofs |
| `propose_admin` | primary admin | Start a two-step admin transfer |
| `accept_admin` | pending admin | Accept the admin role |
| `cancel_admin_transfer` | primary admin | Cancel a pending admin transfer |
| `add_co_admin` | primary admin | Add a co-admin |
| `remove_co_admin` | primary admin | Remove a co-admin |
| `is_admin` | — | Check if an address is admin or co-admin |
| `prune_dispute_votes` | admin | Prune dispute and timeout votes for settled escrows (bounded batch) |

## `get_admin`

Read-only getter for backend health checks and deployment verification. It
returns the active primary admin and includes `pending_admin` when a two-step
admin transfer has been proposed but not yet accepted.

```rust
pub fn get_admin(env: Env) -> Result<AdminView, EscrowError>
```

### `AdminView`

```rust
pub struct AdminView {
    pub admin: Address,
    pub pending_admin: Option<Address>,
}
```

### Errors

| Code | Meaning |
|---|---|
| `EscrowError::NotFound` (2) | Contract has not been initialized |

### No new storage keys, events, migrations, or environment variables

`get_admin` reads existing instance storage keys: `DataKey::Admin` and
`DataKey::PendingAdmin`. It requires no auth and does not mutate state or emit
events.

## `get_timeout_view` (issue #88)

Read-only getter that returns timeout metadata for a single escrow without
mutating any contract state. Safe to call from off-chain indexers and backend
services without auth.

```rust
pub fn get_timeout_view(env: Env, escrow_id: u64) -> Result<EscrowTimeoutView, EscrowError>
```

### `EscrowTimeoutView`

```rust
pub struct EscrowTimeoutView {
    pub escrow_id: BytesN<32>,   // 32-byte order id (same key as other receipts)
    pub timeout_ledger: u32,     // ledger sequence when buyer-refund timeout expires
    pub current_ledger: u32,     // ledger sequence at call time
    pub refundable: bool,        // true only when Funded AND current_ledger >= timeout_ledger
}
```

`refundable` is `true` only when the escrow is still in `Funded` status **and**
`current_ledger >= timeout_ledger`. Terminal states (`Released`, `Refunded`) and
`Disputed` always return `refundable: false`.

### Errors

| Code | Meaning |
|---|---|
| `EscrowError::NotFound` (2) | No escrow exists for the given `escrow_id` |

### No new storage keys or environment variables

`get_timeout_view` reads `DataKey::Escrow(escrow_id)` (existing persistent
storage) and `env.ledger().sequence()`. No new keys, migrations, or environment
variables are required.

## Merchant Cancellation

Merchants (sellers) may cancel an escrow that has been created but not yet funded (`status == Created`).
Cancellation transitions the escrow to `EscrowStatus::Cancelled` (a terminal state) and emits `EscrowCancelledEvent`.

```rust
pub fn cancel(env: Env, escrow_id: u64, caller: Address, reason: Symbol) -> Result<bool, EscrowError>
```

A unilateral `cancel` is refused for a short window after the order is created
(and after a seller acceptance) so that a seller watching the mempool cannot
front-run a buyer's pending `fund`/`deposit` submission. See
[Cancellation protection](#cancellation-protection-issue-355).

### `EscrowCancelledEvent`

```rust
pub struct EscrowCancelledEvent {
    pub escrow_id: BytesN<32>,   // 32-byte order id
    pub cancelled_by: Address,   // merchant address
    pub reason: Symbol,         // short cancellation reason symbol
}
```

### Errors

| Code | Meaning |
|---|---|
| `EscrowError::AlreadyFunded` (28) | Cannot cancel an escrow after funds are locked |
| `EscrowError::AlreadyCancelled` (27) | Escrow has already been cancelled |
| `EscrowError::InvalidStatus` (6) | Escrow is in a state that cannot be cancelled |
| `EscrowError::Unauthorized` (3) | Caller is not the merchant (`seller`) |
| `EscrowError::CancelLockoutActive` (411) | Cancel protection window is running and no agreement or timeout applies |
| `EscrowError::NotFound` (2) | No escrow exists for the given `escrow_id` |

## Cancellation protection (issue #355)

An order is created before the buyer commits funds, so a seller that watches
the mempool could otherwise get a `cancel` in front of a pending
`fund`/`deposit` and invalidate an order the buyer is already committed to.
The contract cannot observe mempool ordering, so it makes the *unilateral*
cancel lose deterministically instead:

- **Protection window.** Every escrow snapshots `cancel_lockout_ledgers`
  (default `10`, admin-configurable, `0` disables) at creation. Inside the
  window a seller can only cancel with the buyer's agreement on-chain, or
  once the escrow's own timeout is reached.
- **Acceptance re-anchors the window.** `accept_order` moves the deadline to
  the acceptance ledger, so a seller who accepts an order cannot shorten the
  buyer's window afterwards.
- **Funding always wins.** `fund`/`deposit` moves the escrow to `Funded`, and
  `cancel` then fails with `AlreadyFunded` in every ledger, protected or not.
- **Fails closed.** An escrow whose protection snapshot is missing (a legacy
  record, or an evicted entry) is treated as if the window never expires;
  only the buyer's agreement or the escrow timeout can clear it.
- **Deterministic previews.** `get_cancel_eligibility` returns exactly the
  answer `cancel` will give, with a `reason` symbol, so clients never have to
  guess at submission order.

```rust
pub struct OrderAcceptanceState {
    pub seller_accepted: bool,
    pub accepted_at_ledger: u32,
    pub cancel_lockout_ledgers: u32,
}

pub struct CancelEligibility {
    pub escrow_id: u64,
    pub eligible: bool,
    pub reason: Symbol,   // ok | agreed | timeout | lockout | funded | cancelled | badstate | notseller | notfound
}
```

### New entry points

```rust
pub fn accept_order(env: Env, escrow_id: u64, seller: Address) -> Result<bool, EscrowError>
pub fn agree_cancel(env: Env, escrow_id: u64, buyer: Address) -> Result<bool, EscrowError>
pub fn get_order_acceptance(env: Env, escrow_id: u64) -> Result<OrderAcceptanceState, EscrowError>
pub fn get_cancel_eligibility(env: Env, escrow_id: u64, caller: Address) -> CancelEligibility
pub fn get_cancel_lockout(env: Env) -> u32
pub fn set_cancel_lockout(env: Env, admin: Address, ledgers: u32) -> Result<bool, EscrowError>
```

`set_cancel_lockout` rejects values above `MAX_CANCEL_LOCKOUT_LEDGERS` (1000)
with `InvalidCancelLockout` and is admin-only; the new default is snapshotted
into each escrow at creation and on acceptance, so it never changes the
protection of an order that is already live.

### Storage keys added

`DataKey::OrderAcceptance(escrow_id)`, `DataKey::CancelLockoutLedger(escrow_id)`,
`DataKey::CancelBuyerAgreement(escrow_id)` and the instance-level
`DataKey::CancelLockoutLedgers`. All are written on the same paths as the
escrow record and bumped with the same TTL thresholds; the agreement key is
only written when a buyer agrees, and is consumed by the `cancel` it
authorized.

## Events

| Topic tuple | Payload struct | Emitted by |
|---|---|---|
| `("escrow", "created")` | `EscrowCreatedEvent` | `create` / `deposit` |
| `("escrow", "metadata")` | `EscrowMetadataEvent` | `create` / `deposit` (when metadata supplied) |
| `("escrow", "cancelled")` | `EscrowCancelledEvent` | `cancel` |
| `("escrow", "accepted", escrow_id)` | `EscrowOrderAcceptedEvent` | `accept_order` |
| `("escrow", "agreed", escrow_id)` | `EscrowCancelAgreedEvent` | `agree_cancel` |
| `("escrow", "released")` | `EscrowReleasedEvent` | `partial_release` / `release` |
| `("escrow", "refunded")` | `EscrowRefundedEvent` | `refund` |
| `("escrow", "disputed")` | `EscrowDisputedEvent` | `dispute` |
| `("escrow", "resolved")` | `EscrowResolvedEvent` | `resolve_dispute` / `resolve_dispute_quorum` |
| `("escrow", "dispsplit")` | `DisputeResolvedEvent` | `resolve_dispute_split` |
| `("escrow", "merkroot", date)` | `BytesN<32>` | `publish_merkle_root` |
| `("escrow", "paused")` | `EscrowPauseChangedEvent` | `set_create_paused` |
| `("admin", "proposed")` | `AdminProposedEvent` | `propose_admin` |
| `("admin", "accepted")` | `AdminAcceptedEvent` | `accept_admin` |
| `("admin", "cancelled")` | `AdminTransferCancelledEvent` | `cancel_admin_transfer` |

## Merkle delivery proofs

Oracles publish one root per UTC epoch day with
`publish_merkle_root(caller, date, root)`. The primary admin and co-admins are
the authorized publishers, and an existing root cannot be overwritten while
stored. Reading or using a root refreshes its persistent-storage TTL. Leaves
are `SHA-256(order_id)`; internal nodes are
SHA-256 of the concatenated left and right 32-byte child hashes. `index` is the
leaf's zero-based position, and `proof` lists siblings from leaf level to root.
A buyer can release a funded escrow with
`release_with_merkle_proof(escrow_id, buyer, date, proof)` only when the proof
matches both the published root and that escrow's order ID.

## Batch escrow creation

`batch_create_escrows(buyer, items)` accepts `BatchEscrowItem` values with an
absolute `timeout_ledger`. The buyer must approve the escrow contract for the
sum of each token's amounts; the contract makes one `transfer_from` call per
distinct token. Batches are limited to 50 entries, and any validation or
allowance failure reverts all created records and transfers.

## Split dispute resolution

`resolve_dispute_split(escrow_id, caller, award)` is admin-only and accepts
`DisputeResolutionAward` amounts for the buyer, seller, and mediator. All
amounts must be non-negative and sum exactly to the escrow balance. The
mediator fee is explicit and no additional platform release fee is charged.
The call transfers each nonzero award, records the buyer amount as refunded
and seller-plus-mediator amounts as released, and emits `DisputeResolvedEvent`.

## Development

```bash
cd escrow

# Run all tests
cargo test

# Build WASM for deployment
cargo build --target wasm32-unknown-unknown --release
```

Buyer escrow pagination uses `BuyerEscrowCount(buyer)` and one persistent
`BuyerEscrowAt(buyer, index)` entry per escrow. This keeps each storage entry
bounded as a buyer accumulates orders; `list_escrows_by_buyer` reads only the
requested page of indices.

Configure the marketplace address with `set_merchant_registry` to block new
escrows for suspended, banned, or closed merchant owners. A configured
registry failure rejects creation. Delivery releases require the admin-set
Ed25519 key and a `SignedDeliveryProof`; the legacy boolean
`evaluate_and_release` entry point remains for ABI compatibility but always
returns `SignedProofRequired`.

The oracle signs the XDR encoding of the ordered payload fields
`(escrow_id, carrier_code, tracking_hash, delivery_timestamp)`. The proof is
accepted only for the configured public key and when the delivery timestamp is
between the escrow's creation timestamp and the current ledger timestamp.
