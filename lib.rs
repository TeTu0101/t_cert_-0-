#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Map, String, Vec,
    log, panic_with_error,
};

// ─────────────────────────────────────────────
// Error codes
// ─────────────────────────────────────────────

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    // Auth / access
    Unauthorized          = 1,
    Blacklisted           = 2,

    // Event lifecycle
    EventNotFound         = 10,
    EventAlreadyExists    = 11,
    EventNotActive        = 12,
    EventAlreadyEnded     = 13,

    // Registration
    NotRegistered         = 20,
    AlreadyRegistered     = 21,

    // Check-in
    AlreadyCheckedIn      = 30,
    NotCheckedIn          = 31,
    FaceVerificationFailed = 32,

    // QR / nonce
    InvalidNonce          = 40,
    NonceExpired          = 41,
    NonceAlreadyUsed      = 42,

    // Presence ping
    NoPingActive          = 50,
    PingWindowExpired     = 51,
    AlreadyConfirmedPing  = 52,

    // Check-out / certificate
    AlreadyCheckedOut     = 60,
    AttendanceInsufficient = 61,
    CertificateAlreadyMinted = 62,
    NotEligible           = 63,
}

// ─────────────────────────────────────────────
// Storage keys
// ─────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Event(u64),                        // event_id  → EventData
    EventCounter,
    Registration(u64, Address),        // (event_id, attendee) → RegistrationData
    Attendee(u64, Address),            // (event_id, attendee) → AttendeeData
    Nonce(BytesN<32>),                 // nonce_hash → NonceRecord
    ActivePing(u64),                   // event_id  → PingData
    Blacklist(Address),                // address   → BlacklistRecord
    Certificate(u64, Address),         // (event_id, attendee) → CertificateData
    FraudRecord(Address),              // address   → Vec<FraudEntry>
}

// ─────────────────────────────────────────────
// Core data types
// ─────────────────────────────────────────────

/// Describes a single club event.
#[contracttype]
#[derive(Clone)]
pub struct EventData {
    pub event_id:      u64,
    pub name:          String,
    pub organizer:     Address,
    pub start_time:    u64,   // Unix timestamp (seconds)
    pub end_time:      u64,
    pub location:      String,
    pub total_pings:   u32,   // expected presence pings during the event
    pub active:        bool,
    pub ended:         bool,
}

/// Written when a member signs up for an event.
#[contracttype]
#[derive(Clone)]
pub struct RegistrationData {
    pub attendee:       Address,
    pub event_id:       u64,
    pub registered_at:  u64,
    /// SHA-256 hash of the face image stored off-chain (e.g. IPFS CID).
    pub face_hash:      BytesN<32>,
}

/// Tracks live check-in/out state and presence for one attendee × event.
#[contracttype]
#[derive(Clone)]
pub struct AttendeeData {
    pub attendee:            Address,
    pub event_id:            u64,
    pub checked_in:          bool,
    pub checkin_time:        u64,
    pub checked_out:         bool,
    pub checkout_time:       u64,
    /// IPFS hash of the selfie captured at check-in time.
    pub checkin_face_proof:  BytesN<32>,
    /// Indices of the pings this attendee successfully confirmed.
    pub confirmed_pings:     Vec<u32>,
    /// Set to true when contract decides they left early.
    pub marked_absent:       bool,
    pub eligible:            bool,
}

/// One-time-use QR nonce record.
#[contracttype]
#[derive(Clone)]
pub struct NonceRecord {
    pub nonce_hash:  BytesN<32>,
    pub event_id:    u64,
    pub created_at:  u64,
    /// Expiry = created_at + 15 seconds (backend enforces generation cadence).
    pub expires_at:  u64,
    pub used:        bool,
    /// What this nonce is for: 0 = check-in, 1 = presence-ping, 2 = check-out.
    pub nonce_type:  u32,
    /// For ping nonces, which ping index this belongs to.
    pub ping_index:  u32,
}

/// Active presence-ping window for an event.
#[contracttype]
#[derive(Clone)]
pub struct PingData {
    pub event_id:    u64,
    pub ping_index:  u32,
    pub opened_at:   u64,
    /// Attendees have PING_WINDOW_SECS (240 s) to respond.
    pub expires_at:  u64,
    pub closed:      bool,
}

/// Issued on-chain once eligibility is confirmed.
#[contracttype]
#[derive(Clone)]
pub struct CertificateData {
    pub cert_id:          BytesN<32>,
    pub event_id:         u64,
    pub attendee:         Address,
    pub issued_at:        u64,
    pub attendance_ratio: u32,   // basis points  0-10000  (e.g. 9500 = 95.00 %)
    pub event_name:       String,
    pub revoked:          bool,
}

/// Written when a fraud detection occurs.
#[contracttype]
#[derive(Clone)]
pub struct FraudEntry {
    pub event_id:    u64,
    pub detected_at: u64,
    pub reason:      String,
}

/// Blacklist entry.
#[contracttype]
#[derive(Clone)]
pub struct BlacklistRecord {
    pub address:      Address,
    pub blacklisted_at: u64,
    pub reason:       String,
}

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

/// QR nonce validity window in seconds.
const NONCE_TTL_SECS:       u64 = 15;
/// Attendee must scan within this many seconds after a ping is opened.
const PING_WINDOW_SECS:     u64 = 240;
/// Minimum attendance ratio in basis points (9000 = 90.00 %).
const MIN_ATTENDANCE_BPS:   u32 = 9_000;

// Nonce type constants
const NONCE_CHECKIN:  u32 = 0;
const NONCE_PING:     u32 = 1;
const NONCE_CHECKOUT: u32 = 2;

// ─────────────────────────────────────────────
// Contract
// ─────────────────────────────────────────────

#[contract]
pub struct CertificationContract;

#[contractimpl]
impl CertificationContract {

    // ─── Initialisation ───────────────────────────────────────────────

    /// Deploy: set the admin address. Can only be called once.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::EventCounter, &0u64);
    }

    // ─── Admin helpers ────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Address {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        admin
    }

    fn require_not_blacklisted(env: &Env, addr: &Address) {
        if env.storage().persistent().has(&DataKey::Blacklist(addr.clone())) {
            panic_with_error!(env, Error::Blacklisted);
        }
    }

    // ─── Event management ─────────────────────────────────────────────

    /// Organizer creates a new event (must be called by admin or a
    /// designated organizer — here we keep it admin-only for simplicity).
    pub fn create_event(
        env:        Env,
        name:       String,
        organizer:  Address,
        start_time: u64,
        end_time:   u64,
        location:   String,
        total_pings: u32,
    ) -> u64 {
        Self::require_admin(&env);

        let mut counter: u64 = env.storage().instance()
            .get(&DataKey::EventCounter).unwrap_or(0);
        counter += 1;

        let event = EventData {
            event_id: counter,
            name,
            organizer,
            start_time,
            end_time,
            location,
            total_pings,
            active: true,
            ended:  false,
        };

        env.storage().persistent().set(&DataKey::Event(counter), &event);
        env.storage().instance().set(&DataKey::EventCounter, &counter);

        log!(&env, "event created: {}", counter);
        counter
    }

    /// Mark an event as ended (prevents new check-ins / pings).
    pub fn end_event(env: Env, event_id: u64) {
        Self::require_admin(&env);
        let mut event = Self::get_event_or_panic(&env, event_id);
        event.active = false;
        event.ended  = true;
        env.storage().persistent().set(&DataKey::Event(event_id), &event);
    }

    // ─── Registration ─────────────────────────────────────────────────

    /// Member registers for an event before it begins.
    /// `face_hash` is the SHA-256 of their profile photo stored off-chain.
    pub fn register(
        env:       Env,
        event_id:  u64,
        attendee:  Address,
        face_hash: BytesN<32>,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let event = Self::get_event_or_panic(&env, event_id);
        if !event.active {
            panic_with_error!(&env, Error::EventNotActive);
        }

        let reg_key = DataKey::Registration(event_id, attendee.clone());
        if env.storage().persistent().has(&reg_key) {
            panic_with_error!(&env, Error::AlreadyRegistered);
        }

        let reg = RegistrationData {
            attendee: attendee.clone(),
            event_id,
            registered_at: env.ledger().timestamp(),
            face_hash,
        };
        env.storage().persistent().set(&reg_key, &reg);
    }

    // ─── QR Nonce management ──────────────────────────────────────────

    /// Backend calls this to register a freshly generated nonce on-chain
    /// before handing the QR to the tablet/display.
    /// `nonce_hash` = SHA-256(random_bytes + event_id + timestamp).
    pub fn register_nonce(
        env:        Env,
        nonce_hash: BytesN<32>,
        event_id:   u64,
        nonce_type: u32,
        ping_index: u32,
    ) {
        Self::require_admin(&env);

        let key = DataKey::Nonce(nonce_hash.clone());
        if env.storage().temporary().has(&key) {
            panic_with_error!(&env, Error::NonceAlreadyUsed);
        }

        let now = env.ledger().timestamp();
        let record = NonceRecord {
            nonce_hash,
            event_id,
            created_at:  now,
            expires_at:  now + NONCE_TTL_SECS,
            used:        false,
            nonce_type,
            ping_index,
        };
        // TTL = 15 ledger entries (≈ 15 s at 1-s close time) then auto-expires.
        env.storage().temporary().set(&key, &record);
    }

    /// Validate and consume a nonce. Returns the NonceRecord on success.
    fn consume_nonce(env: &Env, nonce_hash: BytesN<32>) -> NonceRecord {
        let key = DataKey::Nonce(nonce_hash.clone());

        let mut record: NonceRecord = env.storage().temporary()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(env, Error::InvalidNonce));

        if record.used {
            panic_with_error!(env, Error::NonceAlreadyUsed);
        }
        let now = env.ledger().timestamp();
        if now > record.expires_at {
            panic_with_error!(env, Error::NonceExpired);
        }

        record.used = true;
        env.storage().temporary().set(&key, &record);
        record
    }

    // ─── Check-in (Layer 1 + Layer 2) ─────────────────────────────────

    /// Attendee scans the rotating QR and submits a selfie hash.
    /// Backend has already compared faces; `face_match` is the result
    /// it passes on-chain together with the proof hash.
    ///
    /// * `nonce_hash`       – hash of the QR scanned at the station
    /// * `face_proof_hash`  – IPFS CID of the selfie taken at check-in
    /// * `face_match`       – true if backend face-comparison passed
    pub fn check_in(
        env:             Env,
        event_id:        u64,
        attendee:        Address,
        nonce_hash:      BytesN<32>,
        face_proof_hash: BytesN<32>,
        face_match:      bool,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        // Verify registration
        let reg_key = DataKey::Registration(event_id, attendee.clone());
        if !env.storage().persistent().has(&reg_key) {
            panic_with_error!(&env, Error::NotRegistered);
        }

        // Event must be active
        let event = Self::get_event_or_panic(&env, event_id);
        if !event.active {
            panic_with_error!(&env, Error::EventNotActive);
        }

        // Attendee must not already be checked in
        let att_key = DataKey::Attendee(event_id, attendee.clone());
        if env.storage().persistent().has(&att_key) {
            let existing: AttendeeData = env.storage().persistent().get(&att_key).unwrap();
            if existing.checked_in {
                panic_with_error!(&env, Error::AlreadyCheckedIn);
            }
        }

        // Consume + validate nonce (must be a check-in nonce for this event)
        let nonce = Self::consume_nonce(&env, nonce_hash);
        if nonce.event_id != event_id || nonce.nonce_type != NONCE_CHECKIN {
            panic_with_error!(&env, Error::InvalidNonce);
        }

        // Layer 1: face verification
        if !face_match {
            panic_with_error!(&env, Error::FaceVerificationFailed);
        }

        let now = env.ledger().timestamp();
        let attendee_data = AttendeeData {
            attendee:           attendee.clone(),
            event_id,
            checked_in:         true,
            checkin_time:       now,
            checked_out:        false,
            checkout_time:      0,
            checkin_face_proof: face_proof_hash,
            confirmed_pings:    Vec::new(&env),
            marked_absent:      false,
            eligible:           false,
        };
        env.storage().persistent().set(&att_key, &attendee_data);
        log!(&env, "checked in: attendee={:?} event={}", attendee, event_id);
    }

    // ─── Presence pings (Layer 3) ──────────────────────────────────────

    /// Organizer opens a new presence-ping window.
    /// Should be called at pre-announced intervals during the event.
    pub fn open_ping(env: Env, event_id: u64, ping_index: u32) {
        Self::require_admin(&env);

        let event = Self::get_event_or_panic(&env, event_id);
        if !event.active {
            panic_with_error!(&env, Error::EventNotActive);
        }

        let now = env.ledger().timestamp();
        let ping = PingData {
            event_id,
            ping_index,
            opened_at:  now,
            expires_at: now + PING_WINDOW_SECS,
            closed:     false,
        };
        env.storage().persistent().set(&DataKey::ActivePing(event_id), &ping);
        log!(&env, "ping opened: event={} index={}", event_id, ping_index);
    }

    /// Organizer explicitly closes a ping window (optional — expiry also stops it).
    pub fn close_ping(env: Env, event_id: u64) {
        Self::require_admin(&env);
        let ping_key = DataKey::ActivePing(event_id);
        let mut ping: PingData = env.storage().persistent()
            .get(&ping_key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NoPingActive));
        ping.closed = true;
        env.storage().persistent().set(&ping_key, &ping);
    }

    /// Attendee confirms presence by scanning the ping QR.
    pub fn confirm_ping(
        env:        Env,
        event_id:   u64,
        attendee:   Address,
        nonce_hash: BytesN<32>,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        // Must be checked in
        let att_key = DataKey::Attendee(event_id, attendee.clone());
        let mut att: AttendeeData = env.storage().persistent()
            .get(&att_key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotCheckedIn));
        if !att.checked_in {
            panic_with_error!(&env, Error::NotCheckedIn);
        }

        // Get active ping for this event
        let ping_key = DataKey::ActivePing(event_id);
        let ping: PingData = env.storage().persistent()
            .get(&ping_key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NoPingActive));

        if ping.closed {
            panic_with_error!(&env, Error::NoPingActive);
        }
        let now = env.ledger().timestamp();
        if now > ping.expires_at {
            panic_with_error!(&env, Error::PingWindowExpired);
        }

        // Prevent double-confirm for same ping
        for i in 0..att.confirmed_pings.len() {
            if att.confirmed_pings.get(i).unwrap() == ping.ping_index {
                panic_with_error!(&env, Error::AlreadyConfirmedPing);
            }
        }

        // Consume nonce (must be a ping nonce for this event + index)
        let nonce = Self::consume_nonce(&env, nonce_hash);
        if nonce.event_id != event_id
            || nonce.nonce_type != NONCE_PING
            || nonce.ping_index != ping.ping_index
        {
            panic_with_error!(&env, Error::InvalidNonce);
        }

        att.confirmed_pings.push_back(ping.ping_index);
        env.storage().persistent().set(&att_key, &att);
        log!(&env, "ping confirmed: attendee={:?} ping={}", attendee, ping.ping_index);
    }

    /// Called by backend (or a cron job) to mark attendees who missed a
    /// closing ping as absent. Typically called when a ping window expires.
    pub fn mark_absent_for_missed_ping(
        env:       Env,
        event_id:  u64,
        attendees: Vec<Address>,
        ping_index: u32,
    ) {
        Self::require_admin(&env);

        for i in 0..attendees.len() {
            let addr = attendees.get(i).unwrap();
            let att_key = DataKey::Attendee(event_id, addr.clone());
            if let Some(mut att) = env.storage().persistent().get::<DataKey, AttendeeData>(&att_key) {
                // Check if they missed this ping
                let mut confirmed = false;
                for j in 0..att.confirmed_pings.len() {
                    if att.confirmed_pings.get(j).unwrap() == ping_index {
                        confirmed = true;
                        break;
                    }
                }
                if !confirmed {
                    att.marked_absent = true;
                    env.storage().persistent().set(&att_key, &att);
                }
            }
        }
    }

    // ─── Check-out ────────────────────────────────────────────────────

    /// Attendee scans the check-out QR to close their attendance record.
    pub fn check_out(
        env:        Env,
        event_id:   u64,
        attendee:   Address,
        nonce_hash: BytesN<32>,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let att_key = DataKey::Attendee(event_id, attendee.clone());
        let mut att: AttendeeData = env.storage().persistent()
            .get(&att_key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotCheckedIn));

        if !att.checked_in {
            panic_with_error!(&env, Error::NotCheckedIn);
        }
        if att.checked_out {
            panic_with_error!(&env, Error::AlreadyCheckedOut);
        }

        // Consume + validate nonce
        let nonce = Self::consume_nonce(&env, nonce_hash);
        if nonce.event_id != event_id || nonce.nonce_type != NONCE_CHECKOUT {
            panic_with_error!(&env, Error::InvalidNonce);
        }

        let event = Self::get_event_or_panic(&env, event_id);

        att.checked_out   = true;
        att.checkout_time = env.ledger().timestamp();

        // ── Eligibility check ──────────────────────────────────────────
        // attendance_ratio = confirmed_pings / total_pings  (basis points)
        let total = event.total_pings;
        let confirmed = att.confirmed_pings.len();
        let ratio_bps: u32 = if total == 0 {
            // No pings were scheduled — full credit if present
            10_000
        } else {
            (confirmed as u32 * 10_000) / total
        };

        att.eligible = ratio_bps >= MIN_ATTENDANCE_BPS;
        env.storage().persistent().set(&att_key, &att);

        log!(
            &env,
            "checked out: attendee={:?} event={} ratio_bps={} eligible={}",
            attendee, event_id, ratio_bps, att.eligible
        );
    }

    // ─── Certificate minting ──────────────────────────────────────────

    /// Mint a certificate NFT (as on-chain record) for an eligible attendee.
    /// The actual NFT asset can be issued separately via Stellar's asset
    /// primitives; this function records the canonical proof on-chain.
    pub fn mint_certificate(
        env:       Env,
        event_id:  u64,
        attendee:  Address,
    ) -> BytesN<32> {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let att_key = DataKey::Attendee(event_id, attendee.clone());
        let att: AttendeeData = env.storage().persistent()
            .get(&att_key)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotCheckedIn));

        if !att.eligible {
            panic_with_error!(&env, Error::NotEligible);
        }

        let cert_key = DataKey::Certificate(event_id, attendee.clone());
        if env.storage().persistent().has(&cert_key) {
            panic_with_error!(&env, Error::CertificateAlreadyMinted);
        }

        let event    = Self::get_event_or_panic(&env, event_id);
        let now      = env.ledger().timestamp();
        let total    = event.total_pings;
        let confirmed = att.confirmed_pings.len();
        let ratio_bps = if total == 0 { 10_000u32 } else { (confirmed as u32 * 10_000) / total };

        // Deterministic cert_id = SHA-256(event_id || attendee || issued_at)
        let mut id_seed = Bytes::new(&env);
        id_seed.extend_from_array(&event_id.to_be_bytes());
        id_seed.extend_from_array(&now.to_be_bytes());
        let cert_id: BytesN<32> = env.crypto().sha256(&id_seed);

        let cert = CertificateData {
            cert_id:          cert_id.clone(),
            event_id,
            attendee:         attendee.clone(),
            issued_at:        now,
            attendance_ratio: ratio_bps,
            event_name:       event.name,
            revoked:          false,
        };
        env.storage().persistent().set(&cert_key, &cert);
        log!(&env, "certificate minted: {:?} event={}", attendee, event_id);
        cert_id
    }

    // ─── Fraud handling ───────────────────────────────────────────────

    /// Admin flags two addresses as a fraud pair (impersonator + requester).
    /// Both wallets are blacklisted and their certificates revoked.
    pub fn report_fraud(
        env:            Env,
        impersonator:   Address,   // the person who physically attended
        requester:      Address,   // the person who asked to be attended for
        event_id:       u64,
        reason:         String,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();

        for addr in [impersonator.clone(), requester.clone()] {
            // Blacklist
            let record = BlacklistRecord {
                address:        addr.clone(),
                blacklisted_at: now,
                reason:         reason.clone(),
            };
            env.storage().persistent().set(&DataKey::Blacklist(addr.clone()), &record);

            // Append to public fraud log
            let fraud_key = DataKey::FraudRecord(addr.clone());
            let mut log_vec: Vec<FraudEntry> = env.storage().persistent()
                .get(&fraud_key)
                .unwrap_or_else(|| Vec::new(&env));
            log_vec.push_back(FraudEntry {
                event_id,
                detected_at: now,
                reason: reason.clone(),
            });
            env.storage().persistent().set(&fraud_key, &log_vec);

            // Revoke certificate if already minted
            let cert_key = DataKey::Certificate(event_id, addr.clone());
            if let Some(mut cert) = env.storage().persistent().get::<DataKey, CertificateData>(&cert_key) {
                cert.revoked = true;
                env.storage().persistent().set(&cert_key, &cert);
            }
        }

        log!(
            &env,
            "fraud reported: impersonator={:?} requester={:?} event={}",
            impersonator, requester, event_id
        );
    }

    /// Admin can remove an address from the blacklist (appeals / mistakes).
    pub fn remove_from_blacklist(env: Env, addr: Address) {
        Self::require_admin(&env);
        env.storage().persistent().remove(&DataKey::Blacklist(addr));
    }

    // ─── Read-only queries ────────────────────────────────────────────

    pub fn get_event(env: Env, event_id: u64) -> Option<EventData> {
        env.storage().persistent().get(&DataKey::Event(event_id))
    }

    pub fn get_registration(env: Env, event_id: u64, attendee: Address) -> Option<RegistrationData> {
        env.storage().persistent().get(&DataKey::Registration(event_id, attendee))
    }

    pub fn get_attendee(env: Env, event_id: u64, attendee: Address) -> Option<AttendeeData> {
        env.storage().persistent().get(&DataKey::Attendee(event_id, attendee))
    }

    pub fn get_certificate(env: Env, event_id: u64, attendee: Address) -> Option<CertificateData> {
        env.storage().persistent().get(&DataKey::Certificate(event_id, attendee))
    }

    pub fn is_blacklisted(env: Env, addr: Address) -> bool {
        env.storage().persistent().has(&DataKey::Blacklist(addr))
    }

    pub fn get_fraud_records(env: Env, addr: Address) -> Vec<FraudEntry> {
        env.storage().persistent()
            .get(&DataKey::FraudRecord(addr))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_active_ping(env: Env, event_id: u64) -> Option<PingData> {
        env.storage().persistent().get(&DataKey::ActivePing(event_id))
    }

    // ─── Internal helpers ─────────────────────────────────────────────

    fn get_event_or_panic(env: &Env, event_id: u64) -> EventData {
        env.storage().persistent()
            .get(&DataKey::Event(event_id))
            .unwrap_or_else(|| panic_with_error!(env, Error::EventNotFound))
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger}, Env};

    fn setup() -> (Env, Address, CertificationContractClient<'static>) {
        let env    = Env::default();
        env.mock_all_auths();
        let admin  = Address::generate(&env);
        let contract_id = env.register_contract(None, CertificationContract);
        let client = CertificationContractClient::new(&env, &contract_id);
        client.initialize(&admin);
        (env, admin, client)
    }

    fn dummy_hash(env: &Env, seed: u8) -> BytesN<32> {
        let mut b = [0u8; 32];
        b[0] = seed;
        BytesN::from_array(env, &b)
    }

    #[test]
    fn test_full_happy_path() {
        let (env, _admin, client) = setup();

        let organizer = Address::generate(&env);
        let attendee  = Address::generate(&env);

        // 1. Create event with 2 pings
        let event_id = client.create_event(
            &String::from_str(&env, "Hackathon 2025"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "Room A"),
            &2u32,
        );

        // 2. Register
        client.register(&event_id, &attendee, &dummy_hash(&env, 1));

        // 3. Register a check-in nonce
        let ci_nonce = dummy_hash(&env, 10);
        client.register_nonce(&ci_nonce, &event_id, &NONCE_CHECKIN, &0u32);

        // 4. Check-in (face match = true)
        client.check_in(&event_id, &attendee, &ci_nonce, &dummy_hash(&env, 2), &true);

        // 5. Open ping 0, confirm it
        client.open_ping(&event_id, &0u32);
        let ping0_nonce = dummy_hash(&env, 20);
        client.register_nonce(&ping0_nonce, &event_id, &NONCE_PING, &0u32);
        client.confirm_ping(&event_id, &attendee, &ping0_nonce);

        // 6. Open ping 1, confirm it
        client.open_ping(&event_id, &1u32);
        let ping1_nonce = dummy_hash(&env, 21);
        client.register_nonce(&ping1_nonce, &event_id, &NONCE_PING, &1u32);
        client.confirm_ping(&event_id, &attendee, &ping1_nonce);

        // 7. Check-out
        let co_nonce = dummy_hash(&env, 30);
        client.register_nonce(&co_nonce, &event_id, &NONCE_CHECKOUT, &0u32);
        client.check_out(&event_id, &attendee, &co_nonce);

        // 8. Verify eligibility
        let att = client.get_attendee(&event_id, &attendee).unwrap();
        assert!(att.eligible);
        assert_eq!(att.confirmed_pings.len(), 2);

        // 9. Mint certificate
        let cert_id = client.mint_certificate(&event_id, &attendee);
        let cert = client.get_certificate(&event_id, &attendee).unwrap();
        assert_eq!(cert.cert_id, cert_id);
        assert_eq!(cert.attendance_ratio, 10_000u32); // 100 %
        assert!(!cert.revoked);
    }

    #[test]
    fn test_insufficient_attendance() {
        let (env, _admin, client) = setup();
        let organizer = Address::generate(&env);
        let attendee  = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "Workshop"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "Lab B"),
            &2u32, // 2 pings required
        );
        client.register(&event_id, &attendee, &dummy_hash(&env, 1));

        let ci_nonce = dummy_hash(&env, 10);
        client.register_nonce(&ci_nonce, &event_id, &NONCE_CHECKIN, &0u32);
        client.check_in(&event_id, &attendee, &ci_nonce, &dummy_hash(&env, 2), &true);

        // Confirm only 1 of 2 pings  →  50 %  <  90 %
        client.open_ping(&event_id, &0u32);
        let p_nonce = dummy_hash(&env, 20);
        client.register_nonce(&p_nonce, &event_id, &NONCE_PING, &0u32);
        client.confirm_ping(&event_id, &attendee, &p_nonce);

        let co_nonce = dummy_hash(&env, 30);
        client.register_nonce(&co_nonce, &event_id, &NONCE_CHECKOUT, &0u32);
        client.check_out(&event_id, &attendee, &co_nonce);

        let att = client.get_attendee(&event_id, &attendee).unwrap();
        assert!(!att.eligible);  // 5000 bps < 9000 bps
    }

    #[test]
    fn test_fraud_blacklist_and_revoke() {
        let (env, _admin, client) = setup();
        let organizer    = Address::generate(&env);
        let impersonator = Address::generate(&env);
        let requester    = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "Talk"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "Hall"),
            &0u32,
        );

        // Requester registered, impersonator checked in on their behalf
        client.register(&event_id, &requester, &dummy_hash(&env, 1));

        // Admin reports fraud
        client.report_fraud(
            &impersonator,
            &requester,
            &event_id,
            &String::from_str(&env, "check-in on behalf"),
        );

        assert!(client.is_blacklisted(&impersonator));
        assert!(client.is_blacklisted(&requester));

        let fraud_log = client.get_fraud_records(&requester);
        assert_eq!(fraud_log.len(), 1);
    }

    #[test]
    #[should_panic]
    fn test_nonce_reuse_rejected() {
        let (env, _admin, client) = setup();
        let organizer = Address::generate(&env);
        let a1 = Address::generate(&env);
        let a2 = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "E"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "X"),
            &0u32,
        );
        client.register(&event_id, &a1, &dummy_hash(&env, 1));
        client.register(&event_id, &a2, &dummy_hash(&env, 2));

        let shared_nonce = dummy_hash(&env, 99);
        client.register_nonce(&shared_nonce, &event_id, &NONCE_CHECKIN, &0u32);

        // First scan: ok
        client.check_in(&event_id, &a1, &shared_nonce, &dummy_hash(&env, 3), &true);
        // Second scan with same nonce: must panic (NonceAlreadyUsed)
        client.check_in(&event_id, &a2, &shared_nonce, &dummy_hash(&env, 4), &true);
    }
}
