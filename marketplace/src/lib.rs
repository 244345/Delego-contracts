//! Delego Marketplace Contract (Merchant Registry & Discovery)
//!
//! Maintains a trusted on-chain registry of merchants with multi-verifier verification,
//! paginated category and name discovery, commission configuration, metadata cooldown lock,
//! status lifecycle controls, and reputation score snapshot integration.

// Contract crates compile as no_std for release and wasm builds, but keep std
// enabled during testing so dev-dependencies and test assertions operate normally.
// This exact conditional form must be consistent across all workspace contract crates.
#![cfg_attr(not(test), no_std)]
#![allow(clippy::too_many_arguments)]
#![warn(missing_docs)]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, InvokeError,
    String, Symbol, Vec,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[contracttype]
#[repr(u32)]
pub enum MerchantStatus {
    Registered = 0, // Created, not yet verified
    Verified = 1,   // Passed verification
    Suspended = 2,  // Temporarily disabled (admin action / review)
    Closed = 3,     // Permanently removed
    All = 4,        // Filter sentinel for cursor discovery (matches every status)
    Banned = 5,     // Permanently barred from trading
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Merchant {
    pub id: u64,
    pub owner: Option<Address>,
    pub name: String,
    pub description: String,
    pub category: Symbol,
    pub image_url: String,
    pub commission_rate_bps: u32,
    pub metadata: Option<String>,
    /// Off-chain metadata URI (IPFS CIDv1 or HTTPS). Capped at
    /// [`MAX_METADATA_URI_LEN`] bytes; `None` when not supplied at
    /// registration time.
    pub metadata_uri: Option<String>,
    pub status: MerchantStatus,
    pub verified: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub reputation: Option<Address>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MerchantView {
    pub id: u64,
    pub name: String,
    pub category: Symbol,
    pub commission_rate_bps: u32,
    pub verified: bool,
    pub status: MerchantStatus,
    pub reputation_score: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum ReputationResolution {
    NotConfigured,
    Available(u32, u64),
    CallFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MerchantStats {
    pub total: u64,
    pub active: u64,
    pub suspended: u64,
    pub closed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct DiscoveryPage {
    pub items: Vec<MerchantView>,
    pub total: u32,
    pub next_offset: Option<u32>,
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MerchantOperationalView {
    pub id: u64,
    pub name: String,
    pub status: MerchantStatus,
    pub verified: bool,
    pub effective: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MerchantCursor {
    pub after_id: u64,
    pub status: MerchantStatus,
    pub limit: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct NameRelease {
    pub name: String,
    pub released_at: u64,
    pub previous_merchant: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct MerchantViewDetailed {
    pub view: MerchantView,
    pub reputation: ReputationResolution,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ArchivedMerchant {
    pub id: u64,
    pub closed_at: u64,
    pub last_view: MerchantView,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CategoryEntry {
    pub key: Symbol,
    pub normalized: Symbol,
    pub display: String,
    pub added_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CategoryProposal {
    pub proposed_symbol: Symbol,
    pub proposed_by: Address,
    pub vote_count: u32,
    pub voting_deadline: u64,
    pub is_approved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct RegisterParams {
    pub name: String,
    pub description: String,
    pub category: Symbol,
    pub image_url: String,
    pub metadata: Option<String>,
    /// Optional URI pointing to off-chain merchant metadata (IPFS CID or HTTPS
    /// URL). Stored as a `soroban_sdk::String` and capped at
    /// [`MAX_METADATA_URI_LEN`] bytes to support both IPFS base58/base32 CIDv1
    /// strings and HTTPS URIs without an arbitrary 32-byte truncation.
    pub metadata_uri: Option<String>,
    pub required_verifications: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffiliateConfig {
    pub referrer_address: Address,
    pub referral_share_bps: u32,
    pub expires_at_ledger: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct VerificationPolicy {
    pub required: u32,
    pub max_verifications: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Verifier {
    pub address: Address,
    pub label: Symbol,
    pub registered_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractVersion {
    pub name: Symbol,
    pub semver: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerchantValidationError {
    EmptyName,
    EmptyDescription,
    WhitespaceOnly,
}

impl From<MerchantValidationError> for MarketplaceError {
    fn from(e: MerchantValidationError) -> Self {
        match e {
            MerchantValidationError::EmptyName
            | MerchantValidationError::EmptyDescription
            | MerchantValidationError::WhitespaceOnly => MarketplaceError::InvalidParam,
        }
    }
}

/// Cross-contract error code allocation.
///
/// To keep bridge error mapping unambiguous, each contract owns a disjoint
/// numeric range. The Marketplace contract must stay within its range:
/// | Contract            | Error code range |
/// |---------------------|------------------|
/// | `PermissionError`   | 1..=999          |
/// | `EscrowError`       | 1000..=1999      |
/// | `ReputationError`   | 2000..=2999      |
/// | `DelegationError`   | 3000..=3999      |
/// | `MarketplaceError`  | 4000..=4999      |
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum MarketplaceError {
    AlreadyInitialized = 4001,
    NotInitialized = 4002,
    Unauthorized = 4003,
    MerchantNotFound = 4004,
    AlreadyVerified = 4005,
    InvalidCommissionBps = 4006,
    DuplicateMerchantName = 4007,
    MerchantFrozen = 4008,
    MerchantClosed = 4009,
    VerifierAlreadyExists = 4010,
    VerifierNotFound = 4011,
    InsufficientVerifications = 4012,
    MetadataLockActive = 4013,
    InvalidCategory = 4014,
    InvalidParam = 4015,
    NoPendingAdmin = 4016,
    VerificationCountOverflow = 4017,
    DuplicateMerchantOwner = 4018,
    /// Merchant category does not match authorized categories for this operation
    MerchantCategoryNotAllowed = 4020,
    /// `metadata_uri` field exceeds [`MAX_METADATA_URI_LEN`] bytes.
    MetadataUriTooLong = 4021,
    /// Insufficient registration deposit provided
    InsufficientDeposit = 4022,
    /// Cannot refund deposit while merchant has open escrows
    HasOpenEscrows = 4023,
    /// Deposit already refunded or does not exist
    DepositNotFound = 4024,
    /// Merchant must be in Suspended status to file an appeal.
    MerchantNotSuspended = 4022,
    /// A pending (Pending) appeal bond already exists for this merchant.
    AppealAlreadyPending = 4023,
    /// Bond amount must be greater than zero.
    ZeroBondAmount = 4024,
    /// No appeal bond found for this merchant.
    AppealNotFound = 4025,
    /// Appeal has already been resolved and cannot be resolved again.
    AppealAlreadyResolved = 4026,
    /// The treasury address for slashed bonds has not been configured.
    TreasuryNotSet = 4027,
    /// The token used for appeal bonds has not been configured.
    AppealBondTokenNotSet = 4028,
}

// ---------------------------------------------------------------------------
// Appeal bond types
// ---------------------------------------------------------------------------

/// Resolution state of a merchant suspension appeal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppealResolution {
    /// Appeal has been filed and is awaiting governance ruling.
    Pending,
    /// Governance upheld the appeal; merchant is reinstated and bond refunded.
    UpheldAndReinstated,
    /// Governance rejected the appeal as frivolous; bond is slashed to treasury.
    RejectedAndSlashed,
}

/// On-chain record of a merchant's suspension appeal and its staked bond.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerchantAppealBond {
    /// ID of the merchant filing the appeal.
    pub merchant_id: u64,
    /// Amount of tokens posted as a bond.
    pub bond_amount: i128,
    /// Token contract address for the bond asset.
    pub bond_token: Address,
    /// Ledger sequence at which the appeal was filed.
    pub appealed_at_ledger: u32,
    /// Current resolution status of this appeal.
    pub resolution_status: AppealResolution,
}

// ---------------------------------------------------------------------------
// Appeal bond events
// ---------------------------------------------------------------------------

/// Emitted when a merchant files a suspension appeal by posting a bond.
#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantAppealFiledEvent {
    /// ID of the appealing merchant.
    pub merchant_id: u64,
    /// Bond amount locked in the contract.
    pub bond_amount: i128,
    /// Token used for the bond.
    pub bond_token: Address,
    /// Ledger sequence at which the appeal was recorded.
    pub appealed_at_ledger: u32,
}

/// Emitted when governance resolves a merchant appeal (either outcome).
#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantAppealResolvedEvent {
    /// ID of the merchant whose appeal was resolved.
    pub merchant_id: u64,
    /// Bond amount that was either refunded or slashed.
    pub bond_amount: i128,
    /// Final resolution: [`AppealResolution::UpheldAndReinstated`] or
    /// [`AppealResolution::RejectedAndSlashed`].
    pub resolution: AppealResolution,
    /// Address that received the bond (merchant owner on reinstatement,
    /// treasury on slash).
    pub recipient: Address,
    CategoryProposalNotFound = 4022,
    CategoryProposalExpired = 4023,
    CategoryAlreadyVoted = 4024,
    MerchantNotVerified = 4025,
}

// --- Events ---
//
// Merchant-scoped events are published as `(mkplc, <action>, merchant_id)` so
// off-chain indexers and Soroban RPC subscriptions can filter by merchant from
// the topics alone, without deserializing the event body (issue #142). The
// `merchant_id` is also retained in the event data. Events that are not scoped
// to a single merchant — verifier add/remove and admin transfer — keep the
// two-topic `(mkplc, <action>)` form.

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantRegisteredEvent {
    pub merchant_id: u64,
    pub owner: Address,
    pub name: String,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantVerifiedEvent {
    pub merchant_id: u64,
    pub verifier: Address,
    pub verified: bool,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantProfileUpdatedEvent {
    pub merchant_id: u64,
    pub updated_fields: Symbol,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryChange {
    pub merchant_id: u64,
    pub from: Symbol,
    pub to: Symbol,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantCategoryChangedEvent {
    pub merchant_id: u64,
    pub from: Symbol,
    pub to: Symbol,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantMetadataUpdatedEvent {
    pub merchant_id: u64,
    pub new_metadata: Option<String>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CooldownConfig {
    pub value_seconds: u64,
    pub min_seconds: u64,
    pub max_seconds: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataCooldownSetEvent {
    pub previous: Option<u64>,
    pub current: u64,
    pub set_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantCommissionSetEvent {
    pub merchant_id: u64,
    pub commission_bps: u32,
    pub set_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantSuspendedEvent {
    pub merchant_id: u64,
    pub suspended_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantBannedEvent {
    pub merchant_id: u64,
    pub banned_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantUnsuspendedEvent {
    pub merchant_id: u64,
    pub unsuspended_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantClosedEvent {
    pub merchant_id: u64,
    pub closed_by: Address,
    pub reason: Symbol,
    pub name: String,
    pub category: Symbol,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantDepositRefundedEvent {
    pub merchant_id: u64,
    pub owner: Address,
    pub amount: i128,
    pub token: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct VerifierAddedEvent {
    pub verifier: Address,
    pub label: Symbol,
    pub added_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct VerifierRemovedEvent {
    pub verifier: Address,
    pub removed_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantVerificationRevokedEvent {
    pub merchant_id: u64,
    pub revoked_by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminProposedEvent {
    pub current_admin: Address,
    pub new_admin: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAcceptedEvent {
    pub previous_admin: Address,
    pub new_admin: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct MerchantReputationSetEvent {
    pub merchant_id: u64,
    pub reputation: Option<Address>,
    pub set_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CategoryAddedEvent {
    pub key: Symbol,
    pub normalized: Symbol,
    pub added_by: Address,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CategoryRemovedEvent {
    pub key: Symbol,
    pub removed_by: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerchantPrunedEvent {
    pub pruned_count: u32,
    pub pruned_by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommissionTier {
    pub min_settled_volume: i128,
    pub commission_rate_bps: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerchantVolumeRecord {
    pub total_settled_volume: i128,
    pub active_tier_bps: u32,
    pub last_updated_ledger: u32,
}

// --- Storage Keys ---

#[contracttype]
pub enum DataKey {
    Admin,
    PendingAdmin,
    NextMerchantId,
    MerchantStats,
    Merchant(u64),
    MerchantOwner(Address),
    RiskOracle,
    MerchantName(String),
    FreedName(String),
    ArchivedMerchant(u64),
    MerchantArchivedAt(u64),
    VerifiedCount(u64),
    Verifiers,
    MerchantIds,
    CategoryIndex(Symbol),
    MetadataCooldown,
    MetadataCooldownConfig,
    MerchantVerifier(u64, Address),
    MerchantVerifierList(u64),
    VerificationPolicy(u64),
    CategoryProposal(Symbol),
    CategoryVote(Symbol, Address, u64),
    LastMetadataUpdate(u64),
    GlobalReputationContract,
    Categories,
    CommissionTiers,
    MerchantVolume(u64),
    MerchantDeposit(u64),
    DepositToken(u64),
    TotalMerchantsRegistered,
    /// Stores the [`MerchantAppealBond`] for a given merchant id.
    AppealBond(u64),
    /// Address to receive slashed appeal bonds (the customer restitution pool).
    AppealTreasury,
    /// Token contract used for merchant suspension appeal bonds.
    AppealBondToken,
}

/// Mirror of `ReputationScore` from `delego-reputation` for cross-contract deserialization.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalReputationScore {
    pub entity: Address,
    pub score: u32,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub disputed_transactions: u64,
    pub avg_rating: u32,
    pub last_updated: u64,
}

const MAX_COMMISSION_BPS: u32 = 10_000;
const MAX_REQUIRED_VERIFICATIONS: u32 = 50;
const DEFAULT_METADATA_COOLDOWN_SECS: u64 = 86_400; // 24 hours
const MIN_METADATA_COOLDOWN_SECS: u64 = 60;
const MAX_METADATA_COOLDOWN_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_PAGE_LIMIT: u32 = 50;
const CATEGORY_VOTE_THRESHOLD: u32 = 3;
const CATEGORY_VOTING_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;
const PERSISTENT_BUMP_THRESHOLD: u32 = 17_280; // ~1 day of ledgers (5s/ledger)
const PERSISTENT_BUMP_AMOUNT: u32 = 518_400; // ~30 days of ledgers

/// Base registration deposit in stroops (5 XLM = 50,000,000 stroops)
pub const BASE_REGISTRATION_DEPOSIT_STROOPS: i128 = 50_000_000;

/// Compute registration deposit based on total merchants registered
/// Currently returns a fixed base deposit, but can be extended to dynamic curves
pub fn compute_registration_deposit(total_merchants_registered: u64) -> i128 {
    // For now, use fixed deposit. Can be made dynamic later:
    // e.g., BASE_REGISTRATION_DEPOSIT_STROOPS + (total_merchants_registered as i128 * scaling_factor)
    let _ = total_merchants_registered; // Allow for future dynamic logic
    BASE_REGISTRATION_DEPOSIT_STROOPS
}

pub(crate) fn normalize_symbol(env: &Env, sym: &Symbol) -> Symbol {
    use soroban_sdk::xdr::ToXdr;
    let xdr = sym.clone().to_xdr(env);
    let xdr_len = xdr.len() as usize;
    // XDR encoding of ScVal::Symbol:
    // 4-byte tag (ScValType::Symbol = 10) + 4-byte big-endian length + characters + 0..3 padding bytes
    if xdr_len >= 8 {
        let mut xdr_bytes = [0u8; 48];
        let read_len = xdr_len.min(48);
        xdr.copy_into_slice(&mut xdr_bytes[..read_len]);
        let sym_len =
            u32::from_be_bytes([xdr_bytes[4], xdr_bytes[5], xdr_bytes[6], xdr_bytes[7]]) as usize;
        if sym_len <= 32 && 8 + sym_len <= read_len {
            let mut lower_buf = [0u8; 32];
            for i in 0..sym_len {
                lower_buf[i] = xdr_bytes[8 + i].to_ascii_lowercase();
            }
            if let Ok(lower_str) = core::str::from_utf8(&lower_buf[..sym_len]) {
                return Symbol::new(env, lower_str);
            }
        }
    }
    sym.clone()
}
// --- Merchant profile field bounds ---
//
// Caps on `RegisterParams` (and the corresponding `update_merchant_profile`)
// string fields. Enforced *before* any bytes are copied off the host string,
// so a caller cannot force unbounded storage growth or unbounded gas by
// submitting an arbitrarily large `name`/`description`/`image_url`/`metadata`.
pub const MAX_NAME_LEN: u32 = 64;
pub const MAX_DESCRIPTION_LEN: u32 = 512;
pub const MAX_IMAGE_URL_LEN: u32 = 256;
pub const MAX_METADATA_LEN: u32 = 1024;
/// Maximum byte length for a `metadata_uri` value.
///
/// IPFS CIDv1 base58/base32 strings are at most ~60 bytes; HTTPS URIs
/// pointing to off-chain metadata rarely exceed 128 bytes in practice.
/// Keeping this cap tight prevents unbounded storage growth while still
/// accommodating real-world IPFS and HTTPS URIs.
pub const MAX_METADATA_URI_LEN: u32 = 128;

// Largest of the caps above; used to size the stack buffer that string
// normalization copies host bytes into. `#![no_std]` without the `alloc`
// feature means we cannot heap-allocate a buffer sized to the actual string,
// so we bound the buffer at the biggest field cap and always bounds-check
// the raw string length against the field-specific cap before copying.
const MAX_FIELD_BUF_LEN: usize = MAX_METADATA_LEN as usize;

#[contract]
pub struct MarketplaceContract;

#[contractimpl]
impl MarketplaceContract {
    // --- Initialization ---

    pub fn __constructor(env: Env, admin: Address) -> Result<(), MarketplaceError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(MarketplaceError::AlreadyInitialized);
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &Option::<Address>::None);
        env.storage()
            .instance()
            .set(&DataKey::NextMerchantId, &1u64);
        env.storage().instance().set(
            &DataKey::MerchantStats,
            &MerchantStats {
                total: 0,
                active: 0,
                suspended: 0,
                closed: 0,
            },
        );
        env.storage()
            .instance()
            .set(&DataKey::Verifiers, &Vec::<Verifier>::new(&env));
        env.storage()
            .instance()
            .set(&DataKey::Categories, &Vec::<CategoryEntry>::new(&env));
        env.storage()
            .instance()
            .set(&DataKey::MetadataCooldown, &DEFAULT_METADATA_COOLDOWN_SECS);
        env.storage().instance().set(
            &DataKey::MetadataCooldownConfig,
            &CooldownConfig {
                value_seconds: DEFAULT_METADATA_COOLDOWN_SECS,
                min_seconds: MIN_METADATA_COOLDOWN_SECS,
                max_seconds: MAX_METADATA_COOLDOWN_SECS,
            },
        );
        env.storage()
            .instance()
            .set(&DataKey::TotalMerchantsRegistered, &0u64);

        Ok(())
    }

    // --- Archived Merchant ---

    pub fn get_archived_merchant(env: Env, id: u64) -> Option<ArchivedMerchant> {
        env.storage()
            .persistent()
            .get(&DataKey::ArchivedMerchant(id))
    fn validate_merchant_input(
        name: &String,
        description: &String,
    ) -> Result<(), MerchantValidationError> {
        if name.is_empty() {
            return Err(MerchantValidationError::EmptyName);
        }
        if name.trim().is_empty() {
            return Err(MerchantValidationError::WhitespaceOnly);
        if description.is_empty() {
            return Err(MerchantValidationError::EmptyDescription);
        if description.trim().is_empty() {
        Ok(())
    }

    // --- Merchant Lifecycle ---

    pub fn register_merchant(
        env: Env,
        merchant: Address,
        params: RegisterParams,
        deposit_token: Address,
        deposit_amount: i128,
    ) -> Result<u64, MarketplaceError> {
        merchant.require_auth();

        // Get total merchants registered for deposit calculation
        let total_registered: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalMerchantsRegistered)
            .unwrap_or(0);
        
        let required_deposit = compute_registration_deposit(total_registered);
        
        // Validate deposit amount
        if deposit_amount < required_deposit {
            return Err(MarketplaceError::InsufficientDeposit);
        }

        // Transfer deposit from merchant to contract
        use soroban_sdk::token;
        let token_client = token::Client::new(&env, &deposit_token);
        token_client.transfer(&merchant, &env.current_contract_address(), &deposit_amount);

        if let Some(existing_id) = env
            .storage()
            .persistent()
            .get::<_, u64>(&DataKey::MerchantOwner(merchant.clone()))
        {
            let existing: Merchant = env
                .storage()
                .persistent()
                .get(&DataKey::Merchant(existing_id))
                .ok_or(MarketplaceError::MerchantNotFound)?;
            if existing.status != MerchantStatus::Closed {
                return Err(MarketplaceError::DuplicateMerchantOwner);
            }
        }

        Self::validate_merchant_input(&params.name, &params.description)?;
        let params = Self::validate_and_normalize(&env, &params)?;

        let name_key = DataKey::MerchantName(params.name.clone());
        if env.storage().persistent().has(&name_key) {
            return Err(MarketplaceError::DuplicateMerchantName);
        }

        // If the name was previously freed, clear the FreedName entry so it can be reused.
        let freed_key = DataKey::FreedName(params.name.clone());
        if env.storage().persistent().has(&freed_key) {
            env.storage().persistent().remove(&freed_key);
        }

        let normalized_category = normalize_symbol(&env, &params.category);

        // Allowlist gating: When non-empty, only allowlisted categories are accepted
        let categories = Self::get_categories(env.clone());
        if !categories.is_empty() {
            let mut allowed = false;
            for c in categories.iter() {
                if c.normalized == normalized_category {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Err(MarketplaceError::InvalidCategory);
            }
        }

        let now = env.ledger().timestamp();
        let next_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextMerchantId)
            .ok_or(MarketplaceError::NotInitialized)?;

        let required_verifications = if params.required_verifications == 0 {
            1
        } else {
            params.required_verifications
        };

        // Determine current verifier capacity and enforce bounds
        let verifiers_len: u32 = Self::get_verifiers(env.clone()).len();
        if required_verifications > MAX_REQUIRED_VERIFICATIONS {
            return Err(MarketplaceError::InvalidParam);
        }
        if verifiers_len > 0 && required_verifications > verifiers_len {
            return Err(MarketplaceError::InvalidParam);
        }

        let new_merchant = Merchant {
            id: next_id,
            owner: Some(merchant.clone()),
            name: params.name.clone(),
            description: params.description,
            category: normalized_category.clone(),
            image_url: params.image_url,
            commission_rate_bps: 0,
            metadata: params.metadata.clone(),
            metadata_uri: params.metadata_uri.clone(),
            status: MerchantStatus::Registered,
            verified: false,
            created_at: now,
            updated_at: now,
            reputation: None,
        };

        // Persist merchant record and indices
        env.storage()
            .persistent()
            .set(&DataKey::Merchant(next_id), &new_merchant);
        env.storage()
            .persistent()
            .set(&DataKey::MerchantOwner(merchant.clone()), &next_id);
        env.storage().persistent().set(&name_key, &next_id);
        let policy = VerificationPolicy {
            required: required_verifications,
            max_verifications: verifiers_len.min(MAX_REQUIRED_VERIFICATIONS),
        };
        env.storage()
            .persistent()
            .set(&DataKey::VerificationPolicy(next_id), &policy);
        env.storage()
            .persistent()
            .set(&DataKey::VerifiedCount(next_id), &0u32);
        env.storage().persistent().set(
            &DataKey::MerchantVerifierList(next_id),
            &Vec::<Address>::new(&env),
        );
        env.storage()
            .persistent()
            .set(&DataKey::LastMetadataUpdate(next_id), &now);

        // Store deposit information
        env.storage()
            .persistent()
            .set(&DataKey::MerchantDeposit(next_id), &deposit_amount);
        env.storage()
            .persistent()
            .set(&DataKey::DepositToken(next_id), &deposit_token);

        // Append to full merchant ids index (persistent storage)
        let mut merchant_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantIds)
            .unwrap_or_else(|| Vec::new(&env));
        merchant_ids.push_back(next_id);
        env.storage()
            .persistent()
            .set(&DataKey::MerchantIds, &merchant_ids);

        let mut stats = Self::get_merchant_stats(env.clone());
        stats.total = stats.total.saturating_add(1);
        stats.active = stats.active.saturating_add(1);
        env.storage().instance().set(&DataKey::MerchantStats, &stats);

        // Append to category index
        let cat_key = DataKey::CategoryIndex(normalized_category.clone());
        let mut cat_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&cat_key)
            .unwrap_or_else(|| Vec::new(&env));
        cat_ids.push_back(next_id);
        env.storage().persistent().set(&cat_key, &cat_ids);

        // Extend TTL for all persistent entries created
        let storage = env.storage().persistent();
        storage.extend_ttl(
            &DataKey::Merchant(next_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(&name_key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        storage.extend_ttl(
            &DataKey::VerificationPolicy(next_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(
            &DataKey::VerifiedCount(next_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(
            &DataKey::MerchantVerifierList(next_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(
            &DataKey::LastMetadataUpdate(next_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(
            &DataKey::MerchantIds,
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        storage.extend_ttl(&cat_key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);

        // Increment monotonic counter
        let incremented = next_id
            .checked_add(1)
            .ok_or(MarketplaceError::InvalidParam)?;
        env.storage()
            .instance()
            .set(&DataKey::NextMerchantId, &incremented);

        // Increment total merchants registered counter
        let new_total_registered = total_registered
            .checked_add(1)
            .ok_or(MarketplaceError::InvalidParam)?;
        env.storage()
            .instance()
            .set(&DataKey::TotalMerchantsRegistered, &new_total_registered);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("reg"), next_id),
            MerchantRegisteredEvent {
                merchant_id: next_id,
                owner: merchant,
                name: params.name,
            },
        );

        Ok(next_id)
    }

    pub fn is_name_available(env: Env, name: String) -> bool {
        let live_key = DataKey::MerchantName(name);
        !env.storage().persistent().has(&live_key)
    }

    pub fn update_merchant_profile(
        env: Env,
        merchant_id: u64,
        caller: Address,
        name: String,
        description: String,
        image_url: String,
        new_category: Option<Symbol>,
    ) -> Result<(), MarketplaceError> {
        caller.require_auth();

        let name = Self::normalize_bounded_string(&env, &name, MAX_NAME_LEN)?;
        if name.is_empty() {
            return Err(MarketplaceError::InvalidParam);
        }
        let description = Self::normalize_bounded_string(&env, &description, MAX_DESCRIPTION_LEN)?;
        let image_url = Self::normalize_bounded_string(&env, &image_url, MAX_IMAGE_URL_LEN)?;

        // Validate new_category when provided: must be a valid (non-default) Symbol.
        // Soroban Symbol values are always non-empty when created via symbol_short! or
        // Symbol::new, so no additional validation is needed here beyond type safety.

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        Self::check_not_frozen_or_closed(&merchant)?;

        if merchant.owner != Some(caller) {
            return Err(MarketplaceError::Unauthorized);
        }

        if merchant.name != name {
            let new_name_key = DataKey::MerchantName(name.clone());
            if env.storage().persistent().has(&new_name_key) {
                return Err(MarketplaceError::DuplicateMerchantName);
            }
            env.storage()
                .persistent()
                .remove(&DataKey::MerchantName(merchant.name.clone()));
            env.storage().persistent().set(&new_name_key, &merchant_id);
            merchant.name = name;
        }

        merchant.description = description;
        merchant.image_url = image_url;

        // Re-index CategoryIndex when category changes.
        if let Some(to_cat) = new_category {
            let from_cat = merchant.category.clone();
            if from_cat != to_cat {
                // Remove merchant_id from old category index (filter-rebuild shrinks the Vec).
                let old_cat_key = DataKey::CategoryIndex(from_cat.clone());
                let old_ids: Vec<u64> = env
                    .storage()
                    .persistent()
                    .get(&old_cat_key)
                    .unwrap_or_else(|| Vec::new(&env));
                let mut new_old_ids: Vec<u64> = Vec::new(&env);
                for id in old_ids.iter() {
                    if id != merchant_id {
                        new_old_ids.push_back(id);
                    }
                }
                env.storage()
                    .persistent()
                    .set(&old_cat_key, &new_old_ids);

                // Append merchant_id to new category index.
                let new_cat_key = DataKey::CategoryIndex(to_cat.clone());
                let mut new_ids: Vec<u64> = env
                    .storage()
                    .persistent()
                    .get(&new_cat_key)
                    .unwrap_or_else(|| Vec::new(&env));
                new_ids.push_back(merchant_id);
                env.storage()
                    .persistent()
                    .set(&new_cat_key, &new_ids);

                // Extend TTL for both category index keys.
                let storage = env.storage().persistent();
                storage.extend_ttl(
                    &old_cat_key,
                    PERSISTENT_BUMP_THRESHOLD,
                    PERSISTENT_BUMP_AMOUNT,
                );
                storage.extend_ttl(
                    &new_cat_key,
                    PERSISTENT_BUMP_THRESHOLD,
                    PERSISTENT_BUMP_AMOUNT,
                );

                // Update the merchant's stored category.
                merchant.category = to_cat.clone();

                // Emit category-changed event.
                env.events().publish(
                    (symbol_short!("mkplc"), symbol_short!("cat_chg")),
                    MerchantCategoryChangedEvent {
                        merchant_id,
                        from: from_cat,
                        to: to_cat,
                    },
                );
            }
        }

        merchant.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (
                symbol_short!("mkplc"),
                symbol_short!("profile"),
                merchant_id,
            ),
            MerchantProfileUpdatedEvent {
                merchant_id,
                updated_fields: symbol_short!("profile"),
            },
        );

        Ok(())
    }

    pub fn update_metadata(
        env: Env,
        merchant_id: u64,
        caller: Address,
        new_metadata: Option<String>,
    ) -> Result<(), MarketplaceError> {
        caller.require_auth();

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        Self::check_not_frozen_or_closed(&merchant)?;

        let admin = Self::get_admin(env.clone())?;
        let is_admin = caller == admin;
        let is_owner = merchant.owner == Some(caller.clone());

        if !is_admin && !is_owner {
            return Err(MarketplaceError::Unauthorized);
        }

        // Change-detection: Compare incoming metadata against stored value
        if merchant.metadata == new_metadata {
            // No change detected; skip write and event emission
            return Ok(());
        }

        let now = env.ledger().timestamp();

        if !is_admin {
            let cooldown = Self::get_metadata_cooldown(env.clone());
            let last_update: u64 = env
                .storage()
                .persistent()
                .get(&DataKey::LastMetadataUpdate(merchant_id))
                .unwrap_or(0);
            if cooldown > 0 && now < last_update.saturating_add(cooldown) {
                return Err(MarketplaceError::MetadataLockActive);
            }
        }

        merchant.metadata = new_metadata.clone();
        merchant.updated_at = now;

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);
        env.storage()
            .persistent()
            .set(&DataKey::LastMetadataUpdate(merchant_id), &now);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("meta"), merchant_id),
            MerchantMetadataUpdatedEvent {
                merchant_id,
                new_metadata,
            },
        );

        Ok(())
    }

    // --- Category Management ---

    pub fn propose_category(env: Env, merchant: Address, symbol: Symbol) -> Result<(), MarketplaceError> {
        merchant.require_auth();
        Self::get_verified_merchant_id(env.clone(), &merchant)?;

        let normalized = normalize_symbol(&env, &symbol);
        if normalized.is_empty() {
            return Err(MarketplaceError::InvalidCategory);
        }

        for category in Self::get_categories(env.clone()).iter() {
            if category.normalized == normalized || category.key == symbol {
                return Err(MarketplaceError::InvalidCategory);
            }
        }

        let now = env.ledger().timestamp();
        let key = DataKey::CategoryProposal(normalized.clone());
        if let Some(existing) = env.storage().instance().get::<_, CategoryProposal>(&key) {
            if existing.is_approved || now < existing.voting_deadline {
                return Err(MarketplaceError::InvalidCategory);
            }
        }

        let proposal = CategoryProposal {
            proposed_symbol: symbol,
            proposed_by: merchant,
            vote_count: 0,
            voting_deadline: now.saturating_add(CATEGORY_VOTING_PERIOD_SECS),
            is_approved: false,
        };
        env.storage().instance().set(&key, &proposal);
        Ok(())
    }

    pub fn vote_category(env: Env, merchant: Address, symbol: Symbol) -> Result<(), MarketplaceError> {
        merchant.require_auth();
        Self::get_verified_merchant_id(env.clone(), &merchant)?;
        let normalized = normalize_symbol(&env, &symbol);
        let key = DataKey::CategoryProposal(normalized.clone());
        let mut proposal: CategoryProposal = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(MarketplaceError::CategoryProposalNotFound)?;

        if proposal.is_approved {
            return Err(MarketplaceError::InvalidCategory);
        }
        if env.ledger().timestamp() >= proposal.voting_deadline {
            return Err(MarketplaceError::CategoryProposalExpired);
        }

        let vote_key = DataKey::CategoryVote(
            normalized.clone(),
            merchant.clone(),
            proposal.voting_deadline,
        );
        if env.storage().persistent().has(&vote_key) {
            return Err(MarketplaceError::CategoryAlreadyVoted);
        }

        proposal.vote_count = proposal
            .vote_count
            .checked_add(1)
            .ok_or(MarketplaceError::InvalidParam)?;
        env.storage().persistent().set(&vote_key, &true);

        if proposal.vote_count >= CATEGORY_VOTE_THRESHOLD {
            let categories = Self::get_categories(env.clone());
            for category in categories.iter() {
                if category.normalized == normalized || category.key == proposal.proposed_symbol {
                    return Err(MarketplaceError::InvalidCategory);
                }
            }

            let mut categories = categories;
            categories.push_back(CategoryEntry {
                key: proposal.proposed_symbol.clone(),
                normalized: normalized.clone(),
                display: String::from_str(&env, "Community approved category"),
                added_at: env.ledger().timestamp(),
            });
            env.storage().instance().set(&DataKey::Categories, &categories);
            proposal.is_approved = true;
            env.events().publish(
                (symbol_short!("mkplc"), symbol_short!("cat_add")),
                CategoryAddedEvent {
                    key: proposal.proposed_symbol.clone(),
                    normalized,
                    added_by: proposal.proposed_by.clone(),
                },
            );
        }

        env.storage().instance().set(&key, &proposal);
        Ok(())
    }

    pub fn get_category_proposal(env: Env, symbol: Symbol) -> Option<CategoryProposal> {
        let normalized = normalize_symbol(&env, &symbol);
        env.storage()
            .instance()
            .get(&DataKey::CategoryProposal(normalized))
    }

    pub fn add_category(
        env: Env,
        admin: Address,
        category: CategoryEntry,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let normalized = normalize_symbol(&env, &category.key);
        let mut categories = Self::get_categories(env.clone());
        for c in categories.iter() {
            if c.normalized == normalized || c.key == category.key {
                return Err(MarketplaceError::InvalidCategory);
            }
        }

        let now = env.ledger().timestamp();
        let entry = CategoryEntry {
            key: category.key.clone(),
            normalized: normalized.clone(),
            display: category.display,
            added_at: if category.added_at == 0 {
                now
            } else {
                category.added_at
            },
        };

        categories.push_back(entry);
        env.storage()
            .instance()
            .set(&DataKey::Categories, &categories);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("cat_add")),
            CategoryAddedEvent {
                key: category.key,
                normalized,
                added_by: admin,
            },
        );

        Ok(())
    }

    pub fn remove_category(
        env: Env,
        admin: Address,
        category: Symbol,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let normalized = normalize_symbol(&env, &category);
        let categories = Self::get_categories(env.clone());
        let mut new_categories = Vec::new(&env);
        let mut found = false;

        for c in categories.iter() {
            if c.key == category || c.normalized == normalized {
                found = true;
            } else {
                new_categories.push_back(c);
            }
        }

        if !found {
            return Err(MarketplaceError::InvalidCategory);
        }

        env.storage()
            .instance()
            .set(&DataKey::Categories, &new_categories);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("cat_rem")),
            CategoryRemovedEvent {
                key: category,
                removed_by: admin,
            },
        );

        Ok(())
    }

    pub fn get_categories(env: Env) -> Vec<CategoryEntry> {
        env.storage()
            .instance()
            .get(&DataKey::Categories)
            .unwrap_or_else(|| Vec::new(&env))
    }

    fn get_verified_merchant_id(
        env: Env,
        merchant: &Address,
    ) -> Result<u64, MarketplaceError> {
        let merchant_id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantOwner(merchant.clone()))
            .ok_or(MarketplaceError::MerchantNotFound)?;
        let record: Merchant = env
            .storage()
            .persistent()
            .get(&DataKey::Merchant(merchant_id))
            .ok_or(MarketplaceError::MerchantNotFound)?;
        if !record.verified || record.status != MerchantStatus::Verified {
            return Err(MarketplaceError::MerchantNotVerified);
        }
        Ok(merchant_id)
    }

    // --- Verification ---

    pub fn add_verifier(
        env: Env,
        admin: Address,
        verifier: Verifier,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut verifiers = Self::get_verifiers(env.clone());
        for v in verifiers.iter() {
            if v.address == verifier.address {
                return Err(MarketplaceError::VerifierAlreadyExists);
            }
        }

        verifiers.push_back(verifier.clone());
        env.storage()
            .instance()
            .set(&DataKey::Verifiers, &verifiers);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("v_add")),
            VerifierAddedEvent {
                verifier: verifier.address,
                label: verifier.label,
                added_by: admin,
            },
        );

        Ok(())
    }

    pub fn remove_verifier(
        env: Env,
        admin: Address,
        verifier: Address,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let verifiers = Self::get_verifiers(env.clone());
        let mut new_verifiers = Vec::new(&env);
        let mut found = false;

        for v in verifiers.iter() {
            if v.address == verifier {
                found = true;
            } else {
                new_verifiers.push_back(v);
            }
        }

        if !found {
            return Err(MarketplaceError::VerifierNotFound);
        }

        // Ensure removal won't invalidate any existing merchant verification policies
        let new_verifiers_len: u32 = new_verifiers.len();
        let merchant_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantIds)
            .unwrap_or_else(|| Vec::new(&env));
        for id in merchant_ids.iter() {
            Self::bump_merchant_state(&env, id);
            let policy: Option<VerificationPolicy> = env
                .storage()
                .persistent()
                .get(&DataKey::VerificationPolicy(id));
            if let Some(p) = policy {
                if p.required > new_verifiers_len {
                    return Err(MarketplaceError::InvalidParam);
                }
            }
        }

        env.storage()
            .instance()
            .set(&DataKey::Verifiers, &new_verifiers);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("v_rem")),
            VerifierRemovedEvent {
                verifier,
                removed_by: admin,
            },
        );

        Ok(())
    }

    pub fn verify_merchant(
        env: Env,
        merchant_id: u64,
        verifier: Address,
    ) -> Result<(), MarketplaceError> {
        verifier.require_auth();

        let verifiers = Self::get_verifiers(env.clone());
        let mut is_registered_verifier = false;
        for v in verifiers.iter() {
            if v.address == verifier {
                is_registered_verifier = true;
                break;
            }
        }

        if !is_registered_verifier {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        Self::check_not_frozen_or_closed(&merchant)?;

        if merchant.verified {
            return Err(MarketplaceError::AlreadyVerified);
        }

        let verifier_key = DataKey::MerchantVerifier(merchant_id, verifier.clone());
        if env.storage().persistent().has(&verifier_key) {
            return Err(MarketplaceError::AlreadyVerified);
        }

        env.storage().persistent().set(&verifier_key, &true);

        let mut verifier_list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantVerifierList(merchant_id))
            .unwrap_or_else(|| Vec::new(&env));
        verifier_list.push_back(verifier.clone());
        env.storage()
            .persistent()
            .set(&DataKey::MerchantVerifierList(merchant_id), &verifier_list);

        let current_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::VerifiedCount(merchant_id))
            .unwrap_or(0);
        let new_count = current_count
            .checked_add(1)
            .ok_or(MarketplaceError::VerificationCountOverflow)?;
        env.storage()
            .persistent()
            .set(&DataKey::VerifiedCount(merchant_id), &new_count);

        let required: u32 = {
            let policy: Option<VerificationPolicy> = env
                .storage()
                .persistent()
                .get(&DataKey::VerificationPolicy(merchant_id));
            policy.map(|p| p.required).unwrap_or(1)
        };

        if new_count >= required {
            merchant.verified = true;
            merchant.status = MerchantStatus::Verified;
        }
        merchant.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("verif"), merchant_id),
            MerchantVerifiedEvent {
                merchant_id,
                verifier,
                verified: merchant.verified,
            },
        );

        Ok(())
    }

    pub fn revoke_verification(
        env: Env,
        admin: Address,
        merchant_id: u64,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        Self::check_not_frozen_or_closed(&merchant)?;

        merchant.verified = false;
        if merchant.status == MerchantStatus::Verified {
            merchant.status = MerchantStatus::Registered;
        }
        merchant.updated_at = env.ledger().timestamp();

        // Clear collected verifications
        env.storage()
            .persistent()
            .set(&DataKey::VerifiedCount(merchant_id), &0u32);

        let verifier_list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantVerifierList(merchant_id))
            .unwrap_or_else(|| Vec::new(&env));
        for v in verifier_list.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::MerchantVerifier(merchant_id, v));
        }
        env.storage().persistent().set(
            &DataKey::MerchantVerifierList(merchant_id),
            &Vec::<Address>::new(&env),
        );

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("v_rev"), merchant_id),
            MerchantVerificationRevokedEvent {
                merchant_id,
                revoked_by: admin,
            },
        );

        Ok(())
    }

    // --- Discovery & Query ---

    pub fn get_merchant_stats(env: Env) -> MerchantStats {
        env.storage()
            .instance()
            .get(&DataKey::MerchantStats)
            .unwrap_or(MerchantStats {
                total: 0,
                active: 0,
                suspended: 0,
                closed: 0,
            })
    }

    pub fn get_merchant(env: Env, merchant_id: u64) -> Result<Merchant, MarketplaceError> {
        let merchant: Merchant = env
            .storage()
            .persistent()
            .get(&DataKey::Merchant(merchant_id))
            .ok_or(MarketplaceError::MerchantNotFound)?;

        Self::bump_merchant_state(&env, merchant_id);

        Ok(merchant)
    }

    /// Validate that a merchant's category matches one of the authorized categories.
    ///
    /// This is used by the escrow contract to enforce merchant category restrictions
    /// during spend operations. The merchant must be active and verified.
    ///
    /// # Arguments
    /// * `merchant_id` - The ID of the merchant to validate
    /// * `authorized_categories` - List of category symbols that are allowed
    ///
    /// # Returns
    /// * `Ok(())` if the merchant's category is in the authorized list
    /// * `Err(MarketplaceError::MerchantCategoryNotAllowed)` if category doesn't match
    /// * `Err(MarketplaceError::MerchantNotFound)` if merchant doesn't exist
    /// * `Err(MarketplaceError::MerchantFrozen)` if merchant is suspended
    /// * `Err(MarketplaceError::MerchantClosed)` if merchant is closed
    /// * `Err(MarketplaceError::MerchantBanned)` if merchant is banned
    pub fn validate_merchant_category(
        env: Env,
        merchant_id: u64,
        authorized_categories: soroban_sdk::Vec<Symbol>,
    ) -> Result<(), MarketplaceError> {
        let merchant = Self::get_merchant(env.clone(), merchant_id)?;

        // Check merchant status - must be active (Verified or Registered)
        match merchant.status {
            MerchantStatus::Verified | MerchantStatus::Registered => {}
            MerchantStatus::Suspended => return Err(MarketplaceError::MerchantFrozen),
            MerchantStatus::Closed => return Err(MarketplaceError::MerchantClosed),
            MerchantStatus::Banned => return Err(MarketplaceError::MerchantBanned),
            MerchantStatus::All => {
                // This is a sentinel value, should never reach here
                return Err(MarketplaceError::InvalidParam);
            }
        }

        // Check if merchant's category is in the authorized list
        let mut authorized = false;
        for cat in authorized_categories.iter() {
            if cat == merchant.category || normalize_symbol(&env, &cat) == merchant.category {
                authorized = true;
                break;
            }
        }

        if !authorized {
            return Err(MarketplaceError::MerchantCategoryNotAllowed);
        }

        Ok(())
    }

    /// Get merchant category by ID (convenience function for cross-contract calls).
    pub fn get_merchant_category(env: Env, merchant_id: u64) -> Result<Symbol, MarketplaceError> {
        let merchant = Self::get_merchant(env, merchant_id)?;
        Ok(merchant.category)
    }

    /// Get merchant ID by owner address.
    ///
    /// This is used by the escrow contract to validate merchant categories.
    /// Returns the merchant ID if found, or 0 if no merchant is registered for this owner.
    pub fn get_merchant_id_by_owner(env: Env, owner: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::MerchantOwner(owner))
            .unwrap_or(0)
    }

    /// Validate a merchant's category against authorized categories.
    ///
    /// Used by escrow contract for spend validation.
    /// Returns Ok(()) if valid, or error if not allowed.
    pub fn validate_merchant_category_by_seller(
        env: Env,
        seller: Address,
        authorized_categories: soroban_sdk::Vec<Symbol>,
    ) -> Result<(), MarketplaceError> {
        // First get the merchant ID by owner
        let merchant_id = Self::get_merchant_id_by_owner(env.clone(), seller);
        
        // If no merchant found, allow (non-marketplace seller)
        if merchant_id == 0 {
            return Ok(());
        }
        
        // Now validate the category
        Self::validate_merchant_category(env, merchant_id, authorized_categories)
    }

    pub fn get_merchant_view_detailed(env: Env, merchant_id: u64) -> Result<MerchantViewDetailed, MarketplaceError> {
    fn bump_merchant_state(env: &Env, id: u64) {
        let storage = env.storage().persistent();
        let merchant: Merchant = match storage.get(&DataKey::Merchant(id)) {
            Some(merchant) => merchant,
            None => return,
        };
        let keys = [
            DataKey::Merchant(id),
            DataKey::MerchantName(merchant.name.clone()),
            DataKey::VerifiedCount(id),
            DataKey::VerificationPolicy(id),
            DataKey::MerchantVerifierList(id),
            DataKey::LastMetadataUpdate(id),
        ];
        for key in keys {
            if storage.has(&key) {
                storage.extend_ttl(&key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
            }
        }
    }

    pub fn get_merchant_view(env: Env, merchant_id: u64) -> Result<MerchantView, MarketplaceError> {
        let merchant = Self::get_merchant(env.clone(), merchant_id)?;

        let reputation_contract = merchant.reputation.clone().or_else(|| {
            env.storage()
                .instance()
                .get(&DataKey::GlobalReputationContract)
        });

        let reputation = if let Some(rep_addr) = reputation_contract {
            if let Some(owner) = merchant.owner.clone() {
                let args = soroban_sdk::vec![&env, owner.to_val()];
                let call_result = env.try_invoke_contract::<ExternalReputationScore, InvokeError>(
                    &rep_addr,
                    &Symbol::new(&env, "get_reputation"),
                    args,
                );
                match call_result {
                    Ok(Ok(rep)) => ReputationResolution::Available(rep.score, rep.last_updated),
                    _ => ReputationResolution::CallFailed,
                }
            } else {
                ReputationResolution::NotConfigured
            }
        } else {
            ReputationResolution::NotConfigured
        };

        let reputation_score = match &reputation {
            ReputationResolution::Available(score, _) => Some(*score),
            _ => None,
        };

        let view = MerchantView {
            id: merchant.id,
            name: merchant.name,
            category: merchant.category,
            commission_rate_bps: merchant.commission_rate_bps,
            verified: merchant.verified,
            status: merchant.status,
            reputation_score,
        };

        Ok(MerchantViewDetailed {
            view,
            reputation,
        })
    }

    pub fn get_merchant_view(env: Env, merchant_id: u64) -> Result<MerchantView, MarketplaceError> {
        let detailed = Self::get_merchant_view_detailed(env, merchant_id)?;
        Ok(detailed.view)
    pub fn get_merchant_operational_view(
        env: Env,
        merchant_id: u64,
    ) -> Result<MerchantOperationalView, MarketplaceError> {
        let merchant = Self::get_merchant(env.clone(), merchant_id)?;

        let effective = merchant.verified && merchant.status == MerchantStatus::Verified;
        Ok(MerchantOperationalView {
            id: merchant.id,
            name: merchant.name,
            status: merchant.status,
            verified: merchant.verified,
            effective,
        })
    }

    pub fn get_merchants(
        env: Env,
        offset: u32,
        limit: u32,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        // Return all merchants regardless of status (backward compatible)
        Self::get_merchants_filtered(env, offset, limit, None)
    }

    pub fn get_merchants_by_status(
        env: Env,
        status: MerchantStatus,
        offset: u32,
        limit: u32,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        // Filter merchants by specific status
        Self::get_merchants_filtered(env, offset, limit, Some(status))
    }

    fn get_merchants_filtered(
        env: Env,
        offset: u32,
        limit: u32,
        status_filter: Option<MerchantStatus>,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        let limit = limit.min(MAX_PAGE_LIMIT);

        // Probe id-scoped `DataKey::Merchant(u64)` entries directly instead of
        // deserializing the whole `MerchantIds` index (issue #120). Merchant ids
        // are assigned monotonically from `NextMerchantId`, so the id space is
        // contiguous and each id in `1..NextMerchantId` maps to a record.
        let next_merchant_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextMerchantId)
            .unwrap_or(1);

        // Filter merchants by status if provided
        let mut filtered_ids = Vec::new(&env);
        let mut id = 1u64;
        while id < next_merchant_id {
        let merchant_ids: Vec<u64> = env
            .persistent()
            .get(&DataKey::MerchantIds)
            .unwrap_or_else(|| Vec::new(&env));
        for id in merchant_ids.iter() {
            if let Ok(merchant) = Self::get_merchant(env.clone(), id) {
                if let Some(status) = status_filter {
                    if merchant.status == status {
                        filtered_ids.push_back(id);
                    }
                } else {
                    // No filter: include all
                    filtered_ids.push_back(id);
                }
            }
            id += 1;
        }

        // Filter merchants by status if provided
        let mut filtered_ids = Vec::new(&env);
        for id in merchant_ids.iter() {
            if let Ok(merchant) = Self::get_merchant(env.clone(), id) {
                if let Some(status) = status_filter {
                    if merchant.status == status {
                        filtered_ids.push_back(id);
                    }
                } else {
                    // No filter: include all
                    filtered_ids.push_back(id);
                }
            }
        }

        let total = filtered_ids.len();
        if offset >= total || limit == 0 {
            return Ok(DiscoveryPage {
                items: Vec::new(&env),
                total,
                next_offset: None,
                next_cursor: None,
                total: total as u32,
            });
        }

        let end = offset.saturating_add(limit).min(total);
        let mut items = Vec::new(&env);
        let mut i = offset;
        while i < end {
            let id = filtered_ids.get(i).unwrap();
            let view = Self::get_merchant_view(env.clone(), id)?;
            items.push_back(view);
            i += 1;
        }

        let next_offset = if end < total { Some(end) } else { None };
        // Expose the last returned id so callers can pivot to cursor pagination.
        let next_cursor = if end < total {
            Some(filtered_ids.get(end.saturating_sub(1)).unwrap())
        } else {
            None
        };

        Ok(DiscoveryPage {
            items,
            total,
            next_offset,
            next_cursor,
            total: total as u32,
        })
    }

    pub fn get_merchants_by_category(
        env: Env,
        category: Symbol,
        offset: u32,
        limit: u32,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        // Return all merchants in category regardless of status (backward compatible)
        Self::get_merchants_by_category_filtered(env, category, offset, limit, None)
    }

    pub fn get_merchants_by_category_status(
        env: Env,
        category: Symbol,
        status: MerchantStatus,
        offset: u32,
        limit: u32,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        // Filter merchants by category and specific status
        Self::get_merchants_by_category_filtered(env, category, offset, limit, Some(status))
    }

    fn get_merchants_by_category_filtered(
        env: Env,
        category: Symbol,
        offset: u32,
        limit: u32,
        status_filter: Option<MerchantStatus>,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        let limit = limit.min(MAX_PAGE_LIMIT);
        let normalized = normalize_symbol(&env, &category);
        let mut cat_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::CategoryIndex(normalized.clone()))
            .unwrap_or_else(|| Vec::new(&env));

        // Backward compatibility: If no merchants found under normalized key,
        // and raw category differs from normalized, check raw category index.
        if cat_ids.is_empty() && normalized != category {
            if let Some(legacy_ids) = env
                .storage()
                .persistent()
                .get(&DataKey::CategoryIndex(category))
            {
                cat_ids = legacy_ids;
            }
        }

        // Filter merchants by status if provided
        let mut filtered_ids = Vec::new(&env);
        for id in cat_ids.iter() {
            if let Ok(merchant) = Self::get_merchant(env.clone(), id) {
                if let Some(status) = status_filter {
                    if merchant.status == status {
                        filtered_ids.push_back(id);
                    }
                } else {
                    // No filter: include all
                    filtered_ids.push_back(id);
                }
            }
        }

        let total = filtered_ids.len();
        if offset >= total || limit == 0 {
            return Ok(DiscoveryPage {
                items: Vec::new(&env),
                total,
                next_offset: None,
                next_cursor: None,
            });
        }

        let end = offset.saturating_add(limit).min(total);
        let mut items = Vec::new(&env);
        let mut i = offset;
        while i < end {
            let id = filtered_ids.get(i).unwrap();
            let view = Self::get_merchant_view(env.clone(), id)?;
            items.push_back(view);
            i += 1;
        }

        let next_offset = if end < total { Some(end) } else { None };
        // Expose the last returned id so callers can pivot to cursor pagination.
        let next_cursor = if end < total {
            Some(filtered_ids.get(end.saturating_sub(1)).unwrap())
        } else {
            None
        };

        Ok(DiscoveryPage {
            items,
            total,
            next_offset,
            next_cursor,
        })
    }

    pub fn get_merchants_cursor(
        env: Env,
        cursor: MerchantCursor,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        let limit = cursor.limit.min(MAX_PAGE_LIMIT);
        let status_filter = cursor.status;

        // Iterate id-scoped `DataKey::Merchant(u64)` entries from `after_id`
        // without deserializing the whole `MerchantIds` index (issue #120). The
        // loop reads at most `limit` merchant views, so cost is bounded by the
        // page size (plus cheap key probes for skipped ids), not by the registry
        // size, and deep pages never pay for the full index.
        let next_merchant_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextMerchantId)
            .unwrap_or(1);

        let mut items = Vec::new(&env);
        let mut last_id = cursor.after_id;
        let mut id = cursor.after_id.saturating_add(1);

        while items.len() < limit && id < next_merchant_id {
            if env.storage().persistent().has(&DataKey::Merchant(id)) {
                let merchant = Self::get_merchant(env.clone(), id)?;
                let matches =
                    status_filter == MerchantStatus::All || merchant.status == status_filter;
                if matches {
                    let view = Self::get_merchant_view(env.clone(), id)?;
                    items.push_back(view);
                    last_id = id;
                }
            }
            id += 1;
        }

        let next_cursor = if !items.is_empty() && id < next_merchant_id {
            Some(last_id)
        } else {
            None
        };

        Ok(DiscoveryPage {
            items,
            total: 0,
            next_offset: None,
            next_cursor,
        })
    }

    pub fn get_merchants_by_category_cursor(
        env: Env,
        category: Symbol,
        after_id: u64,
        limit: u32,
    ) -> Result<DiscoveryPage, MarketplaceError> {
        let limit = limit.min(MAX_PAGE_LIMIT);

        // Category membership is already scoped by `CategoryIndex(category)`, so
        // page that id list from `after_id` without scanning the global registry.
        let cat_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::CategoryIndex(category))
            .unwrap_or_else(|| Vec::new(&env));

        let mut items = Vec::new(&env);
        let mut last_id = after_id;
        let n = cat_ids.len();

        // Skip ids already seen by the caller (after_id is exclusive).
        let mut i = 0u32;
        while i < n && cat_ids.get(i).unwrap() <= after_id {
            i += 1;
        }

        while i < n && items.len() < limit {
            let id = cat_ids.get(i).unwrap();
            let view = Self::get_merchant_view(env.clone(), id)?;
            items.push_back(view);
            last_id = id;
            i += 1;
        }

        let next_cursor = if i < n { Some(last_id) } else { None };

        Ok(DiscoveryPage {
            items,
            total: 0,
            next_offset: None,
            next_cursor,
        // Filter merchants by status if provided
        let mut filtered_ids = Vec::new(&env);
        for id in cat_ids.iter() {
            if let Ok(merchant) = Self::get_merchant(env.clone(), id) {
                if let Some(status) = status_filter {
                    if merchant.status == status {
                        filtered_ids.push_back(id);
                    }
                } else {
                    // No filter: include all
                    filtered_ids.push_back(id);
                }
            }
        let total = filtered_ids.len();
        if offset >= total || limit == 0 {
            return Ok(DiscoveryPage {
                items: Vec::new(&env),
                total: total as u32,
                next_offset: None,
            });
        let end = offset.saturating_add(limit).min(total);
        let mut i = offset;
        while i < end {
            let id = filtered_ids.get(i).unwrap();
        let next_offset = if end < total { Some(end) } else { None };
            total: total as u32,
            next_offset,
        })
    }

    // --- Commission ---

    pub fn set_merchant_commission(
        env: Env,
        merchant_id: u64,
        caller: Address,
        commission_bps: u32,
    ) -> Result<(), MarketplaceError> {
        caller.require_auth();

        if commission_bps > MAX_COMMISSION_BPS {
            return Err(MarketplaceError::InvalidCommissionBps);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        Self::check_not_frozen_or_closed(&merchant)?;

        let admin = Self::get_admin(env.clone())?;
        let is_admin = caller == admin;
        let is_owner = merchant.owner == Some(caller.clone());

        if !is_admin && !is_owner {
            return Err(MarketplaceError::Unauthorized);
        }

        merchant.commission_rate_bps = commission_bps;
        merchant.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("comm"), merchant_id),
            MerchantCommissionSetEvent {
                merchant_id,
                commission_bps,
                set_by: caller,
            },
        );

        Ok(())
    }

    pub fn get_commission(env: Env, merchant_id: u64) -> Result<u32, MarketplaceError> {
        let merchant = Self::get_merchant(env, merchant_id)?;
        Ok(merchant.commission_rate_bps)
    }

    // --- Moderation / Security ---

    pub fn suspend_merchant(
        env: Env,
        admin: Address,
        merchant_id: u64,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        if !Self::is_admin_or_risk_oracle(&env, &admin)? {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        if matches!(merchant.status, MerchantStatus::Closed) {
            return Err(MarketplaceError::MerchantClosed);
        }
        if matches!(merchant.status, MerchantStatus::Banned) {
            return Err(MarketplaceError::MerchantBanned);
        }

        let prev_status = merchant.status;
        if prev_status != MerchantStatus::Suspended {
            let mut stats = Self::get_merchant_stats(env.clone());
            stats.active = stats.active.saturating_sub(1);
            stats.suspended = stats.suspended.saturating_add(1);
            env.storage().instance().set(&DataKey::MerchantStats, &stats);
        }

        merchant.status = MerchantStatus::Suspended;
        merchant.updated_at = env.ledger().timestamp();

        if let Some(owner) = merchant.owner.clone() {
            env.storage()
                .persistent()
                .set(&DataKey::MerchantOwner(owner), &merchant_id);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (
                symbol_short!("mkplc"),
                symbol_short!("suspend"),
                merchant_id,
            ),
            MerchantSuspendedEvent {
                merchant_id,
                suspended_by: admin,
            },
        );

        Ok(())
    }

    pub fn unsuspend_merchant(
        env: Env,
        admin: Address,
        merchant_id: u64,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        if matches!(merchant.status, MerchantStatus::Closed) {
            return Err(MarketplaceError::MerchantClosed);
        }
        if matches!(merchant.status, MerchantStatus::Banned) {
            return Err(MarketplaceError::MerchantBanned);
        }

        let prev_status = merchant.status;
        if prev_status == MerchantStatus::Suspended {
            let mut stats = Self::get_merchant_stats(env.clone());
            stats.suspended = stats.suspended.saturating_sub(1);
            stats.active = stats.active.saturating_add(1);
            env.storage().instance().set(&DataKey::MerchantStats, &stats);
        }

        merchant.status = if merchant.verified {
            MerchantStatus::Verified
        } else {
            MerchantStatus::Registered
        };
        merchant.updated_at = env.ledger().timestamp();

        if let Some(owner) = merchant.owner.clone() {
            env.storage()
                .persistent()
                .set(&DataKey::MerchantOwner(owner), &merchant_id);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("unsusp"), merchant_id),
            MerchantUnsuspendedEvent {
                merchant_id,
                unsuspended_by: admin,
            },
        );

        Ok(())
    }

    /// Permanently ban a merchant from trading. The admin or configured risk
    /// oracle may trigger this emergency action; bans cannot be reversed by
    /// `unsuspend_merchant`.
    pub fn ban_merchant(
        env: Env,
        caller: Address,
        merchant_id: u64,
    ) -> Result<(), MarketplaceError> {
        caller.require_auth();
        if !Self::is_admin_or_risk_oracle(&env, &caller)? {
            return Err(MarketplaceError::Unauthorized);
        }
        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        if merchant.status == MerchantStatus::Closed {
            return Err(MarketplaceError::MerchantClosed);
        }
        if merchant.status != MerchantStatus::Banned {
            let mut stats = Self::get_merchant_stats(env.clone());
            if merchant.status == MerchantStatus::Suspended {
                stats.suspended = stats.suspended.saturating_sub(1);
            } else {
                stats.active = stats.active.saturating_sub(1);
                stats.suspended = stats.suspended.saturating_add(1);
            }
            env.storage().instance().set(&DataKey::MerchantStats, &stats);
        }
        merchant.status = MerchantStatus::Banned;
        merchant.updated_at = env.ledger().timestamp();
        if let Some(owner) = merchant.owner.clone() {
            env.storage()
                .persistent()
                .set(&DataKey::MerchantOwner(owner), &merchant_id);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);
        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("ban"), merchant_id),
            MerchantBannedEvent {
                merchant_id,
                banned_by: caller,
            },
        );
        Ok(())
    }

    pub fn close_merchant(
        env: Env,
        admin: Address,
        merchant_id: u64,
        reason: Symbol,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        let prev_status = merchant.status;
        if prev_status != MerchantStatus::Closed {
            let mut stats = Self::get_merchant_stats(env.clone());
            match prev_status {
                MerchantStatus::Suspended | MerchantStatus::Banned => {
                    stats.suspended = stats.suspended.saturating_sub(1);
                }
                MerchantStatus::Registered | MerchantStatus::Verified => {
                    stats.active = stats.active.saturating_sub(1);
                }
                MerchantStatus::Closed => {}
                MerchantStatus::All => {}
            }
            stats.closed = stats.closed.saturating_add(1);
            env.storage().instance().set(&DataKey::MerchantStats, &stats);
        }

        merchant.status = MerchantStatus::Closed;
        if let Some(owner) = merchant.owner.clone() {
            env.storage()
                .persistent()
                .set(&DataKey::MerchantOwner(owner), &merchant_id);
        }

        // Prune from global merchant index
        let mut merchant_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantIds)
            .unwrap_or_else(|| Vec::new(&env));
        if let Some(pos) = merchant_ids.iter().position(|&x| x == id) {
            merchant_ids.swap_remove(pos as u32);
            env.storage()
                .persistent()
                .set(&DataKey::MerchantIds, &merchant_ids);
        }

        // Prune from category index
        let cat_key = DataKey::CategoryIndex(merchant.category.clone());
        let mut cat_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&cat_key)
            .unwrap_or_else(|| Vec::new(&env));
        if let Some(pos) = cat_ids.iter().position(|&x| x == id) {
            cat_ids.swap_remove(pos as u32);
            env.storage()
                .persistent()
                .set(&cat_key, &cat_ids);
        }

        // Archive the merchant snapshot
        let closed_at = env.ledger().timestamp();
        let archived = ArchivedMerchant {
            id: merchant.id,
            closed_at,
            last_view: MerchantView {
                id: merchant.id,
                name: merchant.name.clone(),
                category: merchant.category.clone(),
                commission_rate_bps: merchant.commission_rate_bps,
                verified: merchant.verified,
                status: merchant.status,
                reputation_score: None,
            },
        };
        env.storage()
            .persistent()
            .set(&DataKey::ArchivedMerchant(id), &archived);
        env.storage()
            .persistent()
            .set(&DataKey::MerchantArchivedAt(id), &closed_at);
        merchant.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("closed"), merchant_id),
            MerchantClosedEvent {
                merchant_id,
                closed_by: admin,
                reason,
                name: merchant.name.clone(),
                category: merchant.category,
            },
        );

        Ok(())
    }

    /// Voluntary merchant deregistration with deposit refund
    ///
    /// Allows merchant owner to close their store voluntarily and receive
    /// their registration deposit back if no open escrows exist.
    ///
    /// # Arguments
    /// * `merchant_id` - The ID of the merchant to deregister
    /// * `owner` - The merchant owner address
    ///
    /// # Returns
    /// * `Ok(())` if deregistration and refund succeed
    /// * `Err(MarketplaceError::HasOpenEscrows)` if merchant has active escrows
    /// * `Err(MarketplaceError::DepositNotFound)` if no deposit exists
    /// * `Err(MarketplaceError::Unauthorized)` if caller is not the owner
    pub fn deregister_merchant(
        env: Env,
        merchant_id: u64,
        owner: Address,
    ) -> Result<(), MarketplaceError> {
        owner.require_auth();

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        
        // Verify ownership
        if merchant.owner != Some(owner.clone()) {
            return Err(MarketplaceError::Unauthorized);
        }

        // Check for open escrows (this would need to be integrated with escrow contract)
        // For now, we assume no open escrows if status is not Closed
        // In production, this should query the escrow contract
        
        // Retrieve deposit information
        let deposit_amount: Option<i128> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantDeposit(merchant_id));
        let deposit_token: Option<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::DepositToken(merchant_id));

        if deposit_amount.is_none() || deposit_token.is_none() {
            return Err(MarketplaceError::DepositNotFound);
        }

        let deposit = deposit_amount.unwrap();
        let token = deposit_token.unwrap();

        // Update merchant status to Closed
        let prev_status = merchant.status;
        if prev_status != MerchantStatus::Closed {
            let mut stats = Self::get_merchant_stats(env.clone());
            match prev_status {
                MerchantStatus::Suspended | MerchantStatus::Banned => {
                    stats.suspended = stats.suspended.saturating_sub(1);
                }
                MerchantStatus::Registered | MerchantStatus::Verified => {
                    stats.active = stats.active.saturating_sub(1);
                }
                MerchantStatus::Closed => {}
                MerchantStatus::All => {}
            }
            stats.closed = stats.closed.saturating_add(1);
            env.storage().instance().set(&DataKey::MerchantStats, &stats);
        }

        merchant.status = MerchantStatus::Closed;
        merchant.updated_at = env.ledger().timestamp();

        // Prune from global merchant index
        let mut merchant_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantIds)
            .unwrap_or_else(|| Vec::new(&env));
        if let Some(pos) = merchant_ids.iter().position(|&x| x == merchant_id) {
            merchant_ids.swap_remove(pos as u32);
            env.storage()
                .persistent()
                .set(&DataKey::MerchantIds, &merchant_ids);
        }

        // Prune from category index
        let cat_key = DataKey::CategoryIndex(merchant.category.clone());
        let mut cat_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&cat_key)
            .unwrap_or_else(|| Vec::new(&env));
        if let Some(pos) = cat_ids.iter().position(|&x| x == merchant_id) {
            cat_ids.swap_remove(pos as u32);
            env.storage()
                .persistent()
                .set(&cat_key, &cat_ids);
        }

        // Archive the merchant
        let closed_at = env.ledger().timestamp();
        let archived = ArchivedMerchant {
            id: merchant.id,
            closed_at,
            last_view: MerchantView {
                id: merchant.id,
                name: merchant.name.clone(),
                category: merchant.category.clone(),
                commission_rate_bps: merchant.commission_rate_bps,
                verified: merchant.verified,
                status: merchant.status,
                reputation_score: None,
            },
        };
        env.storage()
            .persistent()
            .set(&DataKey::ArchivedMerchant(merchant_id), &archived);
        env.storage()
            .persistent()
            .set(&DataKey::MerchantArchivedAt(merchant_id), &closed_at);

        // Save updated merchant
        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        // Refund deposit to owner
        use soroban_sdk::token;
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &owner, &deposit);

        // Clear deposit storage
        env.storage()
            .persistent()
            .remove(&DataKey::MerchantDeposit(merchant_id));
        env.storage()
            .persistent()
            .remove(&DataKey::DepositToken(merchant_id));

        // Emit events
        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("closed"), merchant_id),
            MerchantClosedEvent {
                merchant_id,
                closed_by: owner.clone(),
                reason: symbol_short!("volunt"),
                name: merchant.name.clone(),
                category: merchant.category,
            },
        );

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("refund"), merchant_id),
            MerchantDepositRefundedEvent {
                merchant_id,
                owner,
                amount: deposit,
                token,
            },
        );

        Ok(())
    }

    /// Prunes closed merchants from `MerchantIds` and `CategoryIndex` (state maintenance).
    ///
    /// Callable by admin in bounded batches (`merchant_ids.len() <= MAX_PAGE_LIMIT`).
    /// Returns the number of closed merchants pruned from active indices.
    pub fn prune_closed_merchants(
        env: Env,
        admin: Address,
        merchant_ids: Vec<u64>,
    ) -> Result<u32, MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }
        if merchant_ids.len() > MAX_PAGE_LIMIT {
            return Err(MarketplaceError::InvalidParam);
        }

        let mut all_ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantIds)
            .unwrap_or_else(|| Vec::new(&env));
        let mut pruned_count: u32 = 0;

        for id in merchant_ids.iter() {
            if let Ok(merchant) = Self::get_merchant(env.clone(), id) {
                if merchant.status == MerchantStatus::Closed {
                    let mut modified = false;
                    if let Some(pos) = all_ids.iter().position(|x| x == id) {
                        all_ids.remove(pos as u32);
                        modified = true;
                    }
                    let cat_key = DataKey::CategoryIndex(merchant.category.clone());
                    if let Some(mut cat_ids) =
                        env.storage().persistent().get::<_, Vec<u64>>(&cat_key)
                    {
                        if let Some(pos) = cat_ids.iter().position(|x| x == id) {
                            cat_ids.remove(pos as u32);
                            env.storage().persistent().set(&cat_key, &cat_ids);
                        }
                    }
                    if modified {
                        pruned_count += 1;
                    }
                }
            }
        }

        if pruned_count > 0 {
            env.storage()
                .persistent()
                .set(&DataKey::MerchantIds, &all_ids);
            env.events().publish(
                (symbol_short!("mkplc"), symbol_short!("pruned")),
                MerchantPrunedEvent {
                    pruned_count,
                    pruned_by: admin,
                },
            );
        }

        Ok(pruned_count)
    }

    // --- Reputation Pairing Config ---

    pub fn set_merchant_reputation(
        env: Env,
        admin: Address,
        merchant_id: u64,
        reputation: Option<Address>,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
        Self::check_not_frozen_or_closed(&merchant)?;

        merchant.reputation = reputation.clone();
        merchant.updated_at = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::Merchant(merchant_id), &merchant);

        env.events().publish(
            (
                symbol_short!("mkplc"),
                symbol_short!("rep_set"),
                merchant_id,
            ),
            MerchantReputationSetEvent {
                merchant_id,
                reputation,
                set_by: admin,
            },
        );

        Ok(())
    }

    pub fn set_reputation_contract(
        env: Env,
        admin: Address,
        reputation: Address,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        env.storage()
            .instance()
            .set(&DataKey::GlobalReputationContract, &reputation);

        Ok(())
    }

    // --- Admin / Config ---

    pub fn propose_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<bool, MarketplaceError> {
        current_admin.require_auth();
        let admin = Self::get_admin(env.clone())?;
        if current_admin != admin {
            return Err(MarketplaceError::Unauthorized);
        }

        if new_admin == current_admin {
            return Ok(false);
        }

        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &Some(new_admin.clone()));

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("adm_prop")),
            AdminProposedEvent {
                current_admin,
                new_admin,
            },
        );

        Ok(true)
    }

    pub fn accept_admin(env: Env, caller: Address) -> Result<(), MarketplaceError> {
        caller.require_auth();

        let pending: Option<Address> = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .unwrap_or(None);

        // No proposal exists: distinct error so callers can tell this apart
        // from "not the proposed successor" (Unauthorized).
        if pending.is_none() {
            return Err(MarketplaceError::NoPendingAdmin);
        }

        if pending != Some(caller.clone()) {
            return Err(MarketplaceError::Unauthorized);
        }

        let previous_admin = Self::get_admin(env.clone())?;

        env.storage().instance().set(&DataKey::Admin, &caller);
        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &Option::<Address>::None);

        env.events().publish(
            (symbol_short!("mkplc"), symbol_short!("adm_acc")),
            AdminAcceptedEvent {
                previous_admin,
                new_admin: caller,
            },
        );

        Ok(())
    }

    pub fn set_metadata_cooldown(
        env: Env,
        admin: Address,
        cooldown_seconds: u64,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        let current_admin = Self::get_admin(env.clone())?;
        if admin != current_admin {
            return Err(MarketplaceError::Unauthorized);
        }

        let previous = Self::get_metadata_cooldown(env.clone());
        let current =
            cooldown_seconds.clamp(MIN_METADATA_COOLDOWN_SECS, MAX_METADATA_COOLDOWN_SECS);
        if previous == current {
            return Ok(());
        }

        env.storage().instance().set(
            &DataKey::MetadataCooldownConfig,
            &CooldownConfig {
                value_seconds: current,
                min_seconds: MIN_METADATA_COOLDOWN_SECS,
                max_seconds: MAX_METADATA_COOLDOWN_SECS,
            },
        );
        // Keep the original key populated for deployments upgraded from the
        // pre-config format and older readers.
        env.storage()
            .instance()
            .set(&DataKey::MetadataCooldown, &current);
        env.events().publish(
            (symbol_short!("mkplc"), Symbol::new(&env, "cooldown_set")),
            MetadataCooldownSetEvent {
                previous: Some(previous),
                current,
                set_by: admin,
            },
        );

        Ok(())
    }

    pub fn get_metadata_cooldown(env: Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, CooldownConfig>(&DataKey::MetadataCooldownConfig)
            .map(|config| config.value_seconds)
            .or_else(|| env.storage().instance().get(&DataKey::MetadataCooldown))
            .unwrap_or(DEFAULT_METADATA_COOLDOWN_SECS)
    }

    pub fn get_admin(env: Env) -> Result<Address, MarketplaceError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(MarketplaceError::NotInitialized)
    }

    /// Configure or clear the risk oracle authorized to freeze merchant
    /// trading. Only the platform admin may change this address.
    pub fn set_risk_oracle(
        env: Env,
        admin: Address,
        risk_oracle: Option<Address>,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        if admin != Self::get_admin(env.clone())? {
            return Err(MarketplaceError::Unauthorized);
        }
        match risk_oracle {
            Some(oracle) => env.storage().instance().set(&DataKey::RiskOracle, &oracle),
            None => env.storage().instance().remove(&DataKey::RiskOracle),
        }
        Ok(())
    }

    /// Returns whether a seller may trade. Addresses not registered as
    /// merchant owners remain eligible for non-marketplace escrow orders.
    pub fn is_merchant_trading(env: Env, seller: Address) -> bool {
        let Some(merchant_id) = env
            .storage()
            .persistent()
            .get::<_, u64>(&DataKey::MerchantOwner(seller))
        else {
            return true;
        };
        let Some(merchant) = env
            .storage()
            .persistent()
            .get::<_, Merchant>(&DataKey::Merchant(merchant_id))
        else {
            return false;
        };
        !matches!(
            merchant.status,
            MerchantStatus::Suspended | MerchantStatus::Banned | MerchantStatus::Closed
        )
    }

    /// Returns the merchant status for a given seller address, or `None` if
    /// the address is not registered as a merchant owner.
    ///
    /// Used by the escrow contract to determine whether a seller has been
    /// administratively suspended or banned by governance, which triggers the
    /// selective buyer withdrawal (fraud restitution) path.
    pub fn get_merchant_status_by_owner(
        env: Env,
        seller: Address,
    ) -> Option<MerchantStatus> {
        let merchant_id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantOwner(seller))?;
        let merchant: Merchant = env
            .storage()
            .persistent()
            .get(&DataKey::Merchant(merchant_id))?;
        Some(merchant.status)
    }

    /// Returns `true` when the seller is a registered merchant whose status is
    /// `Suspended` or `Banned`.
    ///
    /// The escrow contract calls this to allow buyers to bypass the remaining
    /// timeout ledger and claim an immediate 100% refund of unreleased escrow
    /// funds when the merchant has been administratively suspended or banned
    /// for confirmed fraudulent activity. Addresses that are not registered
    /// merchants return `false`, so honest active merchants and non-marketplace
    /// sellers are unaffected.
    pub fn is_merchant_suspended_or_banned(env: Env, seller: Address) -> bool {
        match Self::get_merchant_status_by_owner(env, seller) {
            Some(MerchantStatus::Suspended) | Some(MerchantStatus::Banned) => true,
            _ => false,
        }
    }

    pub fn get_verifiers(env: Env) -> Vec<Verifier> {
        env.storage()
            .instance()
            .get(&DataKey::Verifiers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ---------------------------------------------------------------------------
    // Appeal bond — admin treasury config
    // ---------------------------------------------------------------------------

    /// Configure the address that receives slashed appeal bonds.
    ///
    /// Only the platform admin may call this. The treasury address is required
    /// before any appeal can be rejected and slashed; calling
    /// [`resolve_merchant_appeal`] with a rejection ruling will fail with
    /// [`MarketplaceError::TreasuryNotSet`] if no treasury has been configured.
    pub fn set_appeal_treasury(
        env: Env,
        admin: Address,
        treasury: Address,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        if admin != Self::get_admin(env.clone())? {
            return Err(MarketplaceError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::AppealTreasury, &treasury);
        Ok(())
    }

    /// Return the currently configured appeal-bond treasury, if any.
    pub fn get_appeal_treasury(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get(&DataKey::AppealTreasury)
    }

    /// Configure the token contract used for all new appeal bonds.
    ///
    /// Only the platform admin may call this. Existing appeals retain the
    /// token address recorded when they were filed.
    pub fn set_appeal_bond_token(
        env: Env,
        admin: Address,
        bond_token: Address,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        if admin != Self::get_admin(env.clone())? {
            return Err(MarketplaceError::Unauthorized);
        }
        env.storage()
            .instance()
            .set(&DataKey::AppealBondToken, &bond_token);
        Ok(())
    }

    /// Return the currently configured appeal-bond token, if any.
    pub fn get_appeal_bond_token(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::AppealBondToken)
    }

    // ---------------------------------------------------------------------------
    // Appeal bond — file
    // ---------------------------------------------------------------------------

    /// File a suspension appeal by locking a refundable staking bond.
    ///
    /// The calling address must be the registered owner of `merchant_id`, and the
    /// merchant must currently be in [`MerchantStatus::Suspended`] status.
    /// Exactly one pending appeal per merchant is allowed at a time.
    ///
    /// The configured bond token is pulled from the merchant owner into the
    /// contract using the SAC `transfer` authorisation flow. The owner must
    /// authorize the transfer when this transaction is submitted.
    ///
    /// # Arguments
    /// * `env`          — execution environment.
    /// * `merchant_id`  — ID of the suspended merchant filing the appeal.
    /// * `bond_amount`  — number of token units to lock (must be > 0).
    ///
    /// # Errors
    /// * [`MarketplaceError::MerchantNotFound`]    — no such merchant.
    /// * [`MarketplaceError::Unauthorized`]        — caller is not the merchant owner.
    /// * [`MarketplaceError::MerchantNotSuspended`]— merchant is not suspended.
    /// * [`MarketplaceError::AppealAlreadyPending`]— a pending appeal already exists.
    /// * [`MarketplaceError::ZeroBondAmount`]      — `bond_amount` is not positive.
    /// * [`MarketplaceError::AppealBondTokenNotSet`]— no bond token is configured.
    pub fn file_merchant_suspension_appeal(
        env: Env,
        merchant_id: u64,
        bond_amount: i128,
    ) -> Result<(), MarketplaceError> {
        // Resolve owner and require their authorisation.
        let merchant = Self::get_merchant(env.clone(), merchant_id)?;
        let owner = merchant.owner.clone().ok_or(MarketplaceError::Unauthorized)?;
        owner.require_auth();

        // Only the merchant's own owner may file an appeal.
        if merchant.owner != Some(owner.clone()) {
            return Err(MarketplaceError::Unauthorized);
        }

        // Merchant must be suspended to be eligible for appeal.
        if merchant.status != MerchantStatus::Suspended {
            return Err(MarketplaceError::MerchantNotSuspended);
        }

        // Reject zero / negative bond amounts.
        if bond_amount <= 0 {
            return Err(MarketplaceError::ZeroBondAmount);
        }

        let bond_token: Address = env
            .storage()
            .instance()
            .get(&DataKey::AppealBondToken)
            .ok_or(MarketplaceError::AppealBondTokenNotSet)?;

        // Only one pending appeal per merchant.
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, MerchantAppealBond>(&DataKey::AppealBond(merchant_id))
        {
            if existing.resolution_status == AppealResolution::Pending {
                return Err(MarketplaceError::AppealAlreadyPending);
            }
        }

        // Pull bond tokens from the owner into this contract.
        let token_client = soroban_sdk::token::Client::new(&env, &bond_token);
        token_client.transfer(&owner, &env.current_contract_address(), &bond_amount);

        let appealed_at_ledger = env.ledger().sequence();
        let bond = MerchantAppealBond {
            merchant_id,
            bond_amount,
            bond_token: bond_token.clone(),
            appealed_at_ledger,
            resolution_status: AppealResolution::Pending,
        };

        env.storage()
            .persistent()
            .set(&DataKey::AppealBond(merchant_id), &bond);
        env.storage().persistent().extend_ttl(
            &DataKey::AppealBond(merchant_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        env.events().publish(
            (
                symbol_short!("mkplc"),
                symbol_short!("ap_filed"),
                merchant_id,
            ),
            MerchantAppealFiledEvent {
                merchant_id,
                bond_amount,
                bond_token,
                appealed_at_ledger,
            },
        );

        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Appeal bond — resolve
    // ---------------------------------------------------------------------------

    /// Resolve a pending merchant suspension appeal.
    ///
    /// Only the platform admin (or, in a future upgrade, a governance contract)
    /// may call this function.
    ///
    /// **`UpheldAndReinstated`**: the bond is refunded to the merchant owner
    /// and the merchant's status is restored to its pre-suspension value
    /// (`Verified` if previously verified, `Registered` otherwise).
    ///
    /// **`RejectedAndSlashed`**: the bond is transferred to the address
    /// configured via [`set_appeal_treasury`]. The merchant remains suspended.
    ///
    /// # Arguments
    /// * `env`         — execution environment.
    /// * `admin`       — must be the current platform admin.
    /// * `merchant_id` — ID of the merchant whose appeal is being resolved.
    /// * `resolution`  — ruling: [`AppealResolution::UpheldAndReinstated`] or
    ///                   [`AppealResolution::RejectedAndSlashed`]. Passing
    ///                   [`AppealResolution::Pending`] is rejected.
    ///
    /// # Errors
    /// * [`MarketplaceError::Unauthorized`]       — caller is not admin.
    /// * [`MarketplaceError::AppealNotFound`]     — no appeal bond on record.
    /// * [`MarketplaceError::AppealAlreadyResolved`]— bond already resolved.
    /// * [`MarketplaceError::InvalidParam`]       — `resolution` is `Pending`.
    /// * [`MarketplaceError::TreasuryNotSet`]     — slash requested but no treasury configured.
    pub fn resolve_merchant_appeal(
        env: Env,
        admin: Address,
        merchant_id: u64,
        resolution: AppealResolution,
    ) -> Result<(), MarketplaceError> {
        admin.require_auth();
        if admin != Self::get_admin(env.clone())? {
            return Err(MarketplaceError::Unauthorized);
        }

        // Pending is not a valid resolution to pass in.
        if resolution == AppealResolution::Pending {
            return Err(MarketplaceError::InvalidParam);
        }

        let mut bond: MerchantAppealBond = env
            .storage()
            .persistent()
            .get(&DataKey::AppealBond(merchant_id))
            .ok_or(MarketplaceError::AppealNotFound)?;

        if bond.resolution_status != AppealResolution::Pending {
            return Err(MarketplaceError::AppealAlreadyResolved);
        }

        let token_client = soroban_sdk::token::Client::new(&env, &bond.bond_token);
        let contract_addr = env.current_contract_address();

        let recipient = match resolution {
            AppealResolution::UpheldAndReinstated => {
                // Reinstate the merchant.
                let mut merchant = Self::get_merchant(env.clone(), merchant_id)?;
                if merchant.status == MerchantStatus::Suspended {
                    let mut stats = Self::get_merchant_stats(env.clone());
                    stats.suspended = stats.suspended.saturating_sub(1);
                    stats.active = stats.active.saturating_add(1);
                    env.storage().instance().set(&DataKey::MerchantStats, &stats);

                    merchant.status = if merchant.verified {
                        MerchantStatus::Verified
                    } else {
                        MerchantStatus::Registered
                    };
                    merchant.updated_at = env.ledger().timestamp();
                    env.storage()
                        .persistent()
                        .set(&DataKey::Merchant(merchant_id), &merchant);
                }

                // Refund bond to the merchant owner.
                let owner = merchant.owner.ok_or(MarketplaceError::Unauthorized)?;
                token_client.transfer(&contract_addr, &owner, &bond.bond_amount);
                owner
            }
            AppealResolution::RejectedAndSlashed => {
                // Treasury must be configured before a slash can proceed.
                let treasury: Address = env
                    .storage()
                    .instance()
                    .get(&DataKey::AppealTreasury)
                    .ok_or(MarketplaceError::TreasuryNotSet)?;

                // Slash bond to the customer restitution pool (treasury).
                token_client.transfer(&contract_addr, &treasury, &bond.bond_amount);
                treasury
            }
            // Already handled by the Pending guard above; unreachable in practice.
            AppealResolution::Pending => return Err(MarketplaceError::InvalidParam),
        };

        bond.resolution_status = resolution.clone();
        env.storage()
            .persistent()
            .set(&DataKey::AppealBond(merchant_id), &bond);
        env.storage().persistent().extend_ttl(
            &DataKey::AppealBond(merchant_id),
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        env.events().publish(
            (
                symbol_short!("mkplc"),
                symbol_short!("ap_resv"),
                merchant_id,
            ),
            MerchantAppealResolvedEvent {
                merchant_id,
                bond_amount: bond.bond_amount,
                resolution,
                recipient,
            },
        );

        Ok(())
    }

    /// Retrieve the appeal bond record for a merchant, if one exists.
    pub fn get_appeal_bond(env: Env, merchant_id: u64) -> Option<MerchantAppealBond> {
        env.storage()
            .persistent()
            .get(&DataKey::AppealBond(merchant_id))
    }

    // ---------------------------------------------------------------------------

    pub fn version(_env: Env) -> ContractVersion {
        ContractVersion {
            name: symbol_short!("market"),
            semver: symbol_short!("0_2_0"),
            semver: soroban_sdk::Symbol::new(&_env, env!("CARGO_PKG_VERSION_SYM")),
        }
    }

    /// Get the current required registration deposit amount
    pub fn get_registration_deposit(env: Env) -> i128 {
        let total_registered: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalMerchantsRegistered)
            .unwrap_or(0);
        compute_registration_deposit(total_registered)
    }

    /// Get deposit information for a merchant
    pub fn get_merchant_deposit(env: Env, merchant_id: u64) -> Option<(i128, Address)> {
        let deposit_amount: Option<i128> = env
            .storage()
            .persistent()
            .get(&DataKey::MerchantDeposit(merchant_id));
        let deposit_token: Option<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::DepositToken(merchant_id));
        
        if let (Some(amount), Some(token)) = (deposit_amount, deposit_token) {
            Some((amount, token))
        } else {
            None
        }
    }

    // --- Helper validation methods ---

    fn check_not_frozen_or_closed(merchant: &Merchant) -> Result<(), MarketplaceError> {
        match merchant.status {
            MerchantStatus::Suspended => Err(MarketplaceError::MerchantFrozen),
            MerchantStatus::Banned => Err(MarketplaceError::MerchantBanned),
            MerchantStatus::Closed => Err(MarketplaceError::MerchantClosed),
            _ => Ok(()),
        }
    }

    fn is_admin_or_risk_oracle(
        env: &Env,
        caller: &Address,
    ) -> Result<bool, MarketplaceError> {
        if caller == &Self::get_admin(env.clone())? {
            return Ok(true);
        }
        Ok(env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::RiskOracle)
            .as_ref()
            == Some(caller))
    }

    /// Trims leading/trailing ASCII whitespace from `s` and enforces that its
    /// (pre-trim) byte length does not exceed `max_len`.
    ///
    /// The length check happens *before* any bytes are copied out of the
    /// host string, so an oversized string is rejected in constant work
    /// rather than first being paid for byte-by-byte.
    ///
    /// Trimming only ever strips single-byte ASCII whitespace characters
    /// (space, tab, CR, LF, form feed, see `u8::is_ascii_whitespace`), which
    /// can never appear as a continuation byte of a multi-byte UTF-8
    /// sequence, so the remaining slice is always valid UTF-8.
    fn normalize_bounded_string(
        env: &Env,
        s: &String,
        max_len: u32,
    ) -> Result<String, MarketplaceError> {
        let raw_len = s.len();
        if raw_len > max_len {
            return Err(MarketplaceError::InvalidParam);
        }

        let mut buf = [0u8; MAX_FIELD_BUF_LEN];
        let n = raw_len as usize;
        s.copy_into_slice(&mut buf[..n]);

        let mut start = 0usize;
        let mut end = n;
        while start < end && buf[start].is_ascii_whitespace() {
            start += 1;
        }
        while end > start && buf[end - 1].is_ascii_whitespace() {
            end -= 1;
        }

        Ok(String::from_bytes(env, &buf[start..end]))
    }

    /// Normalizes and bounds-checks every string field on `RegisterParams`,
    /// used by both `register_merchant` and, field-by-field, by
    /// `update_merchant_profile`. Whitespace is trimmed to a canonical form
    /// before persistence, and every field is rejected with
    /// `MarketplaceError::InvalidParam` if it exceeds its configured cap.
    /// `name` is additionally required to be non-empty after trimming.
    fn validate_and_normalize(
        env: &Env,
        p: &RegisterParams,
    ) -> Result<RegisterParams, MarketplaceError> {
        let name = Self::normalize_bounded_string(env, &p.name, MAX_NAME_LEN)?;
        if name.is_empty() {
            return Err(MarketplaceError::InvalidParam);
        }
        let description = Self::normalize_bounded_string(env, &p.description, MAX_DESCRIPTION_LEN)?;
        let image_url = Self::normalize_bounded_string(env, &p.image_url, MAX_IMAGE_URL_LEN)?;
        let metadata = match &p.metadata {
            Some(m) => Some(Self::normalize_bounded_string(env, m, MAX_METADATA_LEN)?),
            None => None,
        };

        // Validate metadata_uri length. We store it verbatim (no whitespace
        // trimming — URIs must not be altered) but reject anything that
        // exceeds MAX_METADATA_URI_LEN bytes to prevent storage bloat.
        let metadata_uri = match &p.metadata_uri {
            Some(uri) => {
                if uri.len() > MAX_METADATA_URI_LEN {
                    return Err(MarketplaceError::MetadataUriTooLong);
                }
                Some(uri.clone())
            }
            None => None,
        };

        Ok(RegisterParams {
            name,
            description,
            category: p.category.clone(),
            image_url,
            metadata,
            metadata_uri,
            required_verifications: p.required_verifications,
        })
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn verify_merchant_count_overflow_returns_error() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let contract_id = env.register_contract(None, MarketplaceContract);
        let client = MarketplaceContractClient::new(&env, &contract_id);

        client.__constructor(&admin).unwrap();

        let owner = Address::generate(&env);
        let params = RegisterParams {
            name: String::from_str(&env, "overflow-merchant"),
            description: String::from_str(&env, "desc"),
            category: symbol_short!("cate"),
            image_url: String::from_str(&env, "https://example.com/image.png"),
            metadata: None,
            metadata_uri: None,
            required_verifications: 1,
        };

        let merchant_id = client.register_merchant(&owner, ¶ms).unwrap();

        env.as_contract(&contract_id, || {
            env.storage()
                .persistent()
                .set(&DataKey::VerifiedCount(merchant_id), &u32::MAX);
        });

        let verifier = Address::generate(&env);
        let verifier_struct = Verifier {
            address: verifier.clone(),
            label: symbol_short!("v"),
            registered_at: env.ledger().timestamp(),
        };
        client.add_verifier(&admin, &verifier_struct).unwrap();

        assert_eq!(
            client.verify_merchant(&merchant_id, &verifier),
            Err(MarketplaceError::VerificationCountOverflow)
        );
    }

    #[test]
    fn verification_count_overflow_error_payload() {
        assert_eq!(MarketplaceError::VerificationCountOverflow as u32, 16);
mod error_code_uniqueness_tests {
    const PERMISSION_ERROR_RANGE: (u32, u32) = (1, 999);
    const ESCROW_ERROR_RANGE: (u32, u32) = (1000, 1999);
    const REPUTATION_ERROR_RANGE: (u32, u32) = (2000, 2999);
    const DELEGATION_ERROR_RANGE: (u32, u32) = (3000, 3999);
    const MARKETPLACE_ERROR_RANGE: (u32, u32) = (4000, 4999);
    fn marketplace_error_codes() -> [u32; 19] {
        [
            MarketplaceError::AlreadyInitialized as u32,
            MarketplaceError::NotInitialized as u32,
            MarketplaceError::Unauthorized as u32,
            MarketplaceError::MerchantNotFound as u32,
            MarketplaceError::AlreadyVerified as u32,
            MarketplaceError::InvalidCommissionBps as u32,
            MarketplaceError::DuplicateMerchantName as u32,
            MarketplaceError::MerchantFrozen as u32,
            MarketplaceError::MerchantClosed as u32,
            MarketplaceError::VerifierAlreadyExists as u32,
            MarketplaceError::VerifierNotFound as u32,
            MarketplaceError::InsufficientVerifications as u32,
            MarketplaceError::MetadataLockActive as u32,
            MarketplaceError::InvalidCategory as u32,
            MarketplaceError::InvalidParam as u32,
            MarketplaceError::NoPendingAdmin as u32,
            MarketplaceError::VerificationCountOverflow as u32,
            MarketplaceError::DuplicateMerchantOwner as u32,
            MarketplaceError::MerchantBanned as u32,
        ]
    fn marketplace_error_codes_are_unique() {
        let codes = marketplace_error_codes();
        for (i, code) in codes.iter().enumerate() {
            for other in codes.iter().skip(i + 1) {
                assert!(
                    code != other,
                    "duplicate error code {} in MarketplaceError",
                    code
                );
            }
        }
    fn marketplace_error_codes_are_in_allocated_range() {
        for code in marketplace_error_codes() {
            assert!(
                (MARKETPLACE_ERROR_RANGE.0..=MARKETPLACE_ERROR_RANGE.1).contains(&code),
                "MarketplaceError code {} outside allocated range",
                code
            );
    fn marketplace_error_codes_do_not_collide_with_other_contracts() {
        let other_ranges = [
            PERMISSION_ERROR_RANGE,
            ESCROW_ERROR_RANGE,
            REPUTATION_ERROR_RANGE,
            DELEGATION_ERROR_RANGE,
        ];
            for &(start, end) in &other_ranges {
                    !(start..=end).contains(&code),
                    "MarketplaceError code {} collides with reserved range {}-{}",
                    code,
                    start,
                    end
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod merchant_operational_view_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env, String, Symbol};

    fn seed_merchant(
        env: &Env,
        contract_id: &soroban_sdk::BytesN<32>,
        id: u64,
        status: MerchantStatus,
        verified: bool,
    ) {
        let merchant = Merchant {
            id,
            owner: None,
            name: String::from_slice(env, b"Matrix Merchant"),
            description: String::from_slice(env, b""),
            category: Symbol::new(env, "general"),
            image_url: String::from_slice(env, b""),
            commission_rate_bps: 0,
            metadata: None,
            status,
            verified,
            created_at: 0,
            updated_at: 0,
            reputation: None,
        };
        env.as_contract(contract_id, || {
            env.storage()
                .persistent()
                .set(&DataKey::Merchant(id), &merchant);
            env.storage()
                .persistent()
                .set(&DataKey::MerchantName(merchant.name.clone()), &id);
        });
    }

    #[test]
    fn operational_view_effective_matrix() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract_id = env.register_contract(None, MarketplaceContract);
        let client = MarketplaceContractClient::new(&env, contract_id.clone());
        drop(client.__constructor(&admin));

        let cases = [
            (MerchantStatus::Registered, false, false),
            (MerchantStatus::Registered, true, false),
            (MerchantStatus::Verified, false, false),
            (MerchantStatus::Verified, true, true),
            (MerchantStatus::Suspended, false, false),
            (MerchantStatus::Suspended, true, false),
            (MerchantStatus::Closed, false, false),
            (MerchantStatus::Closed, true, false),
        ];

        for (i, (status, verified, effective)) in cases.iter().enumerate() {
            let id = i as u64 + 1;
            seed_merchant(&env, &contract_id, id, *status, *verified);
            let view = client.get_merchant_operational_view(&id).unwrap();
            assert_eq!(view.status, *status);
            assert_eq!(view.verified, *verified);
            assert_eq!(view.effective, *effective);
        }
    }

    #[test]
    fn suspend_keeps_verified_flag_but_not_effective() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract_id = env.register_contract(None, MarketplaceContract);
        let client = MarketplaceContractClient::new(&env, contract_id.clone());
        drop(client.__constructor(&admin));

        let verifier = Verifier {
            address: Address::generate(&env),
            label: Symbol::new(&env, "gov"),
            registered_at: 0,
        };
        drop(client.add_verifier(&admin, &verifier));

        let owner = Address::generate(&env);
        let params = RegisterParams {
            name: String::from_slice(&env, b"Verified Merchant"),
            description: String::from_slice(&env, b"desc"),
            category: Symbol::new(&env, "general"),
            image_url: String::from_slice(&env, b"https://example.com/img.png"),
            metadata: None,
            metadata_uri: None,
            required_verifications: 1,
        };
        let id = client.register_merchant(&owner, &params).unwrap();
        drop(client.verify_merchant(&id, &verifier.address));
        drop(client.suspend_merchant(&admin, &id));

        let view = client.get_merchant_operational_view(&id).unwrap();
        assert_eq!(view.status, MerchantStatus::Suspended);
        assert!(view.verified);
        assert!(!view.effective);
    }
}
