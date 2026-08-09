//! `MachineResource`, `HeartbeatStatus`, `ComponentResource`,
//! `ProcessResource`, and the `Pid` newtype.
//!
//! Intended contents (see `docs/plans/tamga-rust.plan.md` §G, §I):
//!
//! - `MachineResource`: `fingerprint`, `name`, `ip`, `hostname`, `platform`,
//!   `cores`, `memory`, `disk`, `metadata`, `heartbeat_status`, relationship
//!   `license`.
//! - `HeartbeatStatus`: `NOT_STARTED` → `ALIVE` → `DEAD` → `RESURRECTED`.
//!   Window is a **hardcoded 600s (10 min)**, not driven by
//!   `policy.heartbeat_duration`. `DEAD` should be treated as "machine
//!   likely deleted server-side — re-activate rather than retry ping."
//! - `ComponentResource`: `machine_id`, `fingerprint`, `name`, `metadata`.
//! - `ProcessResource`: `machine_id`, `pid`, `metadata`.
//! - `Pid` newtype: the wire format is a **string, not an integer** —
//!   provide `From<u32>`/`From<i32>` that stringify on serialize, so callers
//!   holding a native numeric PID don't have to hand-format it. Process
//!   heartbeat window is a hardcoded **30 seconds** (much shorter than the
//!   machine's 600s) with no resurrection grace period — a dead process row
//!   is deleted immediately, no `KEEP_DEAD` equivalent.

/// The `machines` JSON:API resource. Stub — see module doc comment above.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MachineResource {
    _private: (),
}

/// Machine heartbeat state machine. Stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum HeartbeatStatus {
    /// Placeholder — replaced by the real 4-variant enum
    /// (`NOT_STARTED`/`ALIVE`/`DEAD`/`RESURRECTED`).
    #[serde(other)]
    Unknown,
}

/// The `components` JSON:API resource. Stub.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ComponentResource {
    _private: (),
}

/// The `processes` JSON:API resource. Stub.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ProcessResource {
    _private: (),
}

/// Process ID newtype. The wire format is a JSON **string**, not a number —
/// this type exists so callers can pass a native `u32`/`i32` and have it
/// stringify correctly on serialize. Stub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pid(pub(crate) String);
