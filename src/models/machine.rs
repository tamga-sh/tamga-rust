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
#[derive(Debug, Clone, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Deserialize)]
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
