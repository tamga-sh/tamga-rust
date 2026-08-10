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

/// The `machines` JSON:API resource: `{ id, type, attributes }`. Field set
/// matches `tamga-api`'s actual `MachineResource`/`MachineAttributes`
/// serializer (`src/features/machines/serializer.rs`) — no `relationships`
/// object, same as [`crate::models::license::LicenseResource`].
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

/// Attributes of a [`MachineResource`], matching `tamga-api`'s
/// `MachineAttributes` field-for-field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MachineAttributes {
    /// Unique per `(account_id, license_id, fingerprint)`.
    pub fingerprint: String,
    /// CPU core count, if reported at registration.
    pub cores: Option<i32>,
    /// Memory in bytes, if reported.
    pub memory: Option<i64>,
    /// Disk in bytes, if reported.
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
/// `Resurrected`. The window is a **hardcoded 600s (10 min)**, not driven
/// by `policy.heartbeat_duration`. Treat `Dead` as "machine likely deleted
/// server-side — re-activate rather than retry ping," per
/// `docs/plans/tamga-rust.plan.md` §G.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// Never pinged.
    NotStarted,
    /// Pinged within the 600s window.
    Alive,
    /// Window elapsed since the last ping.
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
/// set matches `tamga-api`'s actual `ComponentResource`/`ComponentAttributes`
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
/// matches `tamga-api`'s actual `ProcessResource`/`ProcessAttributes`
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
/// is no `heartbeat_status` field — a process's aliveness is entirely a
/// function of `last_heartbeat_at` versus the hardcoded 30s window (see
/// [`Pid`]'s doc comment); a dead process row is deleted immediately, not
/// tracked in a `DEAD`/`RESURRECTED` state like machines.
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
/// ⚠️ Process heartbeat window is a **hardcoded 30 seconds** — much shorter
/// than a machine's 600s — with **no resurrection grace period**: a dead
/// process row is deleted immediately, no `KEEP_DEAD` equivalent. An SDK
/// monitoring a long-running process must ping at least every ~10s to stay
/// safely inside this window.
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
