//! `MachineResource`, `HeartbeatStatus`, `ComponentResource`,
//! `ProcessResource`, and the `Pid` newtype.
//!
//! Contents:
//!
//! - `MachineResource`: `fingerprint`, `name`, `ip`, `hostname`, `platform`,
//!   `cores`, `memory`, `disk`, `metadata`, `heartbeat_status`, relationship
//!   `license`. ⚠️ `memory` and `disk` are **megabytes**, not bytes — the
//!   server's own column comment says so, and these are the values that
//!   feed the licence's `machines_memory_count`/`machines_disk_count`
//!   totals and the `MEMORY_LIMIT_EXCEEDED`/`DISK_LIMIT_EXCEEDED` checks.
//! - `HeartbeatStatus`: `NOT_STARTED` → `ALIVE` → `DEAD` → `RESURRECTED`.
//!   The server's window **is** `policy.heartbeat_duration`, falling back to
//!   600s (10 min) only when that column is null — but this crate cannot read
//!   it and assumes the 600s fallback throughout, so on a shorter-window
//!   policy the caller must pick the ping interval itself. `DEAD` means
//!   **only** "the last ping is older than that window" — it is not a
//!   tombstone. Under the default policy (`require_heartbeat = false`)
//!   nothing is ever culled, so a machine can report `DEAD` indefinitely
//!   with its row and its seat still in place. Keep pinging through `DEAD`;
//!   the ping succeeds and revives the machine. A `404` from the ping is the
//!   only row-is-gone signal.
//! - `ComponentResource`: `machine_id`, `fingerprint`, `name`, `metadata`.
//! - `ProcessResource`: `machine_id`, `pid`, `metadata`.
//! - `Pid` newtype: the wire format is a **string, not an integer** —
//!   provide `From<u32>`/`From<i32>` that stringify on serialize, so callers
//!   holding a native numeric PID don't have to hand-format it. The 30s
//!   process heartbeat window exists only in a worker the server never
//!   runs: **no process row is ever reaped**, so a leaked process holds its
//!   slot against `max_processes` until a client deletes it explicitly.

/// The `machines` JSON:API resource: `{ id, type, attributes }`. Field set
/// matches the Tamga API's actual `MachineResource`/`MachineAttributes`
/// serializer — no `relationships` object, same as
/// [`crate::models::license::LicenseResource`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachineResource {
    /// UUIDv7 machine ID.
    pub id: uuid::Uuid,
    /// Always `"machines"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: MachineAttributes,
}

/// Attributes of a [`MachineResource`], matching the Tamga API's
/// `MachineAttributes` field-for-field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachineAttributes {
    /// Unique per `(account_id, license_id, fingerprint)`.
    pub fingerprint: String,
    /// CPU core count, if reported at registration.
    pub cores: Option<i32>,
    /// Memory in **megabytes**, if reported. Not bytes: reporting 16 GiB
    /// as `17179869184` inflates the licence's `machines_memory_count` by
    /// a factor of 1,048,576 and trips `MEMORY_LIMIT_EXCEEDED` on the next
    /// activation against the same licence.
    pub memory: Option<i64>,
    /// Disk in **megabytes**, if reported — same units and same failure
    /// mode as `memory`.
    pub disk: Option<i64>,
    /// IP address, if reported.
    pub ip: Option<String>,
    /// Reported hostname, if any.
    pub hostname: Option<String>,
    /// Reported OS/platform string, if any.
    pub platform: Option<String>,
    /// Optional display name.
    pub name: Option<String>,
    /// Machine heartbeat state — see [`HeartbeatStatus`].
    pub heartbeat_status: HeartbeatStatus,
    /// Timestamp of the last `ping-heartbeat` call.
    pub last_heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Server-computed next-expected-heartbeat deadline, if derivable.
    ///
    /// ⚠️ Not a reliable source for the policy's real heartbeat window. The
    /// server computes it from the window carried on the row, and the create,
    /// ping-heartbeat and reset-heartbeat queries — the only machine
    /// responses this crate can reach — do not join the policy, so this is
    /// `last_heartbeat_at + 600s` even under a policy that asks for less.
    pub next_heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Timestamp of the last machine-file checkout.
    pub last_check_out_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
}

/// Machine heartbeat state machine: `NotStarted` → `Alive` → `Dead` →
/// `Resurrected`.
///
/// ⚠️ **The window is policy-driven, and this crate cannot discover it.**
/// Server-side it is `policy.heartbeat_duration`, with 600s (10 min) used
/// only as the fallback when that column is null: `effective_window_secs`
/// prefers the policy value, and the cull job's claim query selects on
/// `COALESCE(p.heartbeat_duration, 600)`. Nothing in this crate reads it —
/// there is no `get_policy` and no `get_machine` — so every interval this
/// crate's documentation suggests is computed against the 600s fallback.
///
/// Do not try to recover the real window from `next_heartbeat_at` either.
/// The server derives that field from the window carried on the row, and the
/// policy join is present only on the read queries this crate exposes no
/// route for; the create, ping-heartbeat and reset-heartbeat paths all omit
/// it, so on every machine response reachable from here `next_heartbeat_at`
/// is `last_heartbeat_at + 600s` whatever the policy actually says. **On a
/// policy with a shorter window, a caller pinging on the 600s assumption
/// pings far too slowly and its machines go `Dead` on schedule.** Learn the
/// window out of band — from whoever provisions the policy — and set the
/// interval explicitly.
///
/// ⚠️ **`Dead` is a staleness report, not a tombstone.** The server computes
/// it purely from `last_heartbeat_at` versus the window and never consults
/// `policy.require_heartbeat` on the way, but the cull job that would
/// actually remove the row bails out unless `require_heartbeat` is set — and
/// that column defaults to `false`. On a default policy nothing is ever
/// culled, so a machine reports `Dead` **forever** while its row, and the
/// seat it holds against the licence, are still there.
///
/// A scheduler must therefore **keep pinging through `Dead`**.
/// [`crate::Client::ping_heartbeat`] is a bare `last_heartbeat_at = NOW()`
/// write with no resurrection check, so it succeeds against a `Dead` machine
/// and revives it. The row-is-gone signal is a `404`
/// ([`crate::TamgaError::NotFound`]) from the ping itself — hang
/// re-activation off that, never off `Dead`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// Never pinged.
    NotStarted,
    /// Pinged within the effective window — `policy.heartbeat_duration`,
    /// else the 600s fallback. See the type-level doc.
    Alive,
    /// Window elapsed since the last ping — and nothing more. Says nothing
    /// about whether the row still exists; see the type-level doc.
    Dead,
    /// Was `Dead`, but a new ping arrived within the policy's resurrection
    /// grace period — see
    /// [`crate::models::policy::HeartbeatResurrectionStrategy`].
    Resurrected,
    /// Any wire value not matching a known variant — lenient
    /// deserialization for forward-compatibility.
    Unknown(String),
}

impl<'de> serde::Deserialize<'de> for HeartbeatStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "NOT_STARTED" => HeartbeatStatus::NotStarted,
            "ALIVE" => HeartbeatStatus::Alive,
            "DEAD" => HeartbeatStatus::Dead,
            "RESURRECTED" => HeartbeatStatus::Resurrected,
            other => HeartbeatStatus::Unknown(other.to_string()),
        })
    }
}

impl serde::Serialize for HeartbeatStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            HeartbeatStatus::NotStarted => "NOT_STARTED",
            HeartbeatStatus::Alive => "ALIVE",
            HeartbeatStatus::Dead => "DEAD",
            HeartbeatStatus::Resurrected => "RESURRECTED",
            HeartbeatStatus::Unknown(s) => s,
        };
        serializer.serialize_str(s)
    }
}

#[cfg(test)]
mod heartbeat_status_tests {
    use super::*;

    #[test]
    fn deserializes_all_4_known_wire_strings() {
        let cases = [
            ("\"NOT_STARTED\"", HeartbeatStatus::NotStarted),
            ("\"ALIVE\"", HeartbeatStatus::Alive),
            ("\"DEAD\"", HeartbeatStatus::Dead),
            ("\"RESURRECTED\"", HeartbeatStatus::Resurrected),
        ];
        for (wire, expected) in cases {
            let parsed: HeartbeatStatus = serde_json::from_str(wire).unwrap();
            assert_eq!(parsed, expected, "wire value {wire}");
        }
    }

    #[test]
    fn deserializes_unknown_value_to_unknown_variant() {
        let parsed: HeartbeatStatus = serde_json::from_str("\"FUTURE_STATE\"").unwrap();
        assert_eq!(parsed, HeartbeatStatus::Unknown("FUTURE_STATE".to_string()));
    }
}

/// The `components` JSON:API resource: `{ id, type, attributes }`. Field
/// set matches the Tamga API's actual `ComponentResource`/`ComponentAttributes`
/// serializer — no `relationships` object, same pattern as the other
/// resources in this crate.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ComponentResource {
    /// UUIDv7 component ID.
    pub id: uuid::Uuid,
    /// Always `"components"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: ComponentAttributes,
}

/// Attributes of a [`ComponentResource`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ComponentAttributes {
    /// Unique per `(account_id, machine_id, fingerprint)`.
    pub fingerprint: String,
    /// Display name.
    pub name: String,
    /// The owning machine's ID.
    pub machine_id: uuid::Uuid,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
}

/// The `processes` JSON:API resource: `{ id, type, attributes }`. Field set
/// matches the Tamga API's actual `ProcessResource`/`ProcessAttributes`
/// serializer.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProcessResource {
    /// UUIDv7 process ID.
    pub id: uuid::Uuid,
    /// Always `"processes"`.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The resource's attribute bag.
    pub attributes: ProcessAttributes,
}

/// Attributes of a [`ProcessResource`]. Unlike a [`MachineResource`], there
/// is no `heartbeat_status` field, and there is no server-side state machine
/// behind one either: `last_heartbeat_at` is written on create and on every
/// ping, serialized back out, and **never read by any live code path**. No
/// equivalent of `DEAD`/`RESURRECTED` is ever computed for a process, and no
/// process row is ever deleted by the server — see [`Pid`]'s doc comment.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProcessAttributes {
    /// The process ID, as a wire string — see [`Pid`].
    pub pid: String,
    /// The owning machine's ID.
    pub machine_id: uuid::Uuid,
    /// A process starts `ALIVE` immediately at creation (unlike a machine,
    /// which starts `NOT_STARTED`) — this timestamp is set on creation, not
    /// left `None` until a first ping.
    pub last_heartbeat_at: chrono::DateTime<chrono::Utc>,
    /// Arbitrary caller-set metadata.
    pub metadata: serde_json::Value,
    /// Creation timestamp.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Last-updated timestamp.
    pub updated: chrono::DateTime<chrono::Utc>,
}

/// Process ID newtype. The wire format is a JSON **string**, not a number —
/// this type exists so callers holding a native numeric PID don't have to
/// hand-format it; `From<u32>`/`From<i32>` stringify on construction.
///
/// ⚠️ **The server does not currently reap process rows.** A 30-second
/// window and a delete-on-expiry sweep are both written — much shorter than
/// a machine's 600s fallback, with no resurrection grace period and no
/// `KEEP_DEAD` equivalent — but the worker holding them has no call site and
/// the job scheduler wires no process tick, so as shipped nothing runs it:
/// no process is ever marked dead, no `process.heartbeat.dead` event is ever
/// emitted, and no row is ever removed. `last_heartbeat_at` is written and
/// echoed back, never acted on.
///
/// The practical consequence is a leak, not an eviction: a process registered
/// by [`crate::Client::create_process`] increments the licence's
/// `machines_process_count` and holds that slot against the policy's
/// `max_processes` **forever**, however long ago it stopped pinging. Only an
/// explicit delete releases it, and this crate exposes no method for that
/// today, so a caller here has no way to release the slot — track it as a
/// gap, and register only what is worth tracking. Keeping a PID stable across
/// restarts at least bounds the damage: re-registering the same one is
/// refused with [`crate::TamgaError::PidTaken`] rather than creating a second
/// row, so the original row and its one slot are what stay in use.
///
/// Keep [`crate::Client::ping_process`] on a ~10s timer regardless. The
/// reaper is written and needs only a scheduler entry to go live, so a client
/// that stops pinging is relying on a bug staying unfixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pid(pub(crate) String);

impl Pid {
    /// Borrows the wire string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        Pid(pid.to_string())
    }
}

impl From<i32> for Pid {
    fn from(pid: i32) -> Self {
        Pid(pid.to_string())
    }
}

impl From<String> for Pid {
    fn from(pid: String) -> Self {
        Pid(pid)
    }
}

impl serde::Serialize for Pid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Pid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Pid)
    }
}

#[cfg(test)]
mod pid_tests {
    use super::*;

    #[test]
    fn from_u32_stringifies() {
        let pid: Pid = 1234u32.into();
        assert_eq!(pid.as_str(), "1234");
    }

    #[test]
    fn from_i32_stringifies() {
        let pid: Pid = 1234i32.into();
        assert_eq!(pid.as_str(), "1234");
    }

    #[test]
    fn round_trips_through_serde_as_a_json_string() {
        let pid: Pid = 1234u32.into();
        let json = serde_json::to_string(&pid).unwrap();
        assert_eq!(json, "\"1234\"");
        let parsed: Pid = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pid);
    }
}
