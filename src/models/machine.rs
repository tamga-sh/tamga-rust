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
//!   600s (10 min) only when that column is null; the write responses carry
//!   the fallback, so read the real one with
//!   [`crate::Client::effective_heartbeat_window`]. `DEAD` means **only**
//!   "the last ping is older than that window" — it is not a tombstone. Under
//!   the default policy (`require_heartbeat = false`) nothing is ever culled,
//!   so a machine stays `DEAD` indefinitely with its row and its seat still
//!   in place. A response can only fail to say `DEAD` when it derives the
//!   status from a `last_heartbeat_at` that same request just wrote — ping,
//!   reset, create. A verified machine file, an offline proof, `get_machine`,
//!   `list_machines` and even `update_machine` (a write that never touches
//!   the heartbeat column) all can. Never stop the ping loop on a status; a
//!   `404` from the ping is the only terminal signal.
//! - `ComponentResource`: `machine_id`, `fingerprint`, `name`, `metadata`.
//! - `ProcessResource`: `machine_id`, `pid`, `metadata`.
//! - `Pid` newtype: the wire format is a **string, not an integer** —
//!   provide `From<u32>`/`From<i32>` that stringify on serialize, so callers
//!   holding a native numeric PID don't have to hand-format it. The 30s
//!   process heartbeat window exists only in a worker the server never
//!   runs: **no process row is ever reaped**, so a leaked process holds its
//!   slot against `max_processes` until a client deletes it explicitly with
//!   [`crate::Client::delete_process`].

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
    ///
    /// `Dead` is unreachable on a response the server derived from a
    /// `last_heartbeat_at` it just wrote — create, ping-heartbeat,
    /// reset-heartbeat. Everywhere else it is a real staleness verdict and
    /// **can be `Dead`**: a verified machine file,
    /// [`crate::Client::generate_offline_proof`],
    /// [`crate::Client::get_machine`], [`crate::Client::list_machines`], and
    /// — despite being a write — [`crate::Client::update_machine`], which
    /// never touches the heartbeat column. Match exhaustively either way.
    pub heartbeat_status: HeartbeatStatus,
    /// Timestamp of the last `ping-heartbeat` call.
    pub last_heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Server-computed next-expected-heartbeat deadline, if derivable.
    ///
    /// ⚠️ Which window this reflects depends on the route, and it is a
    /// *different* split from the one `heartbeat_status` follows. The create,
    /// ping-heartbeat, reset-heartbeat **and update** queries do not join
    /// `policies`, so there this is `last_heartbeat_at + 600s` even under a
    /// policy that asks for less — not a usable source for the real window.
    /// Machine checkout, offline proof, `GET /machines/{id}` and the machine
    /// list all resolve through a policy-joined read, so there it is the
    /// genuine deadline and `next_heartbeat_at - last_heartbeat_at` recovers
    /// the effective window. See
    /// [`MachineAttributes::observed_heartbeat_window`].
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

impl MachineAttributes {
    /// The heartbeat window this response was judged against, recovered as
    /// `next_heartbeat_at - last_heartbeat_at`, or `None` when either
    /// timestamp is absent.
    ///
    /// ⚠️ **Only trustworthy on a response the server built from a read.**
    /// `next_heartbeat_at` is derived from `Machine::effective_window_secs()`,
    /// which reads a `policy_heartbeat_duration` column populated only when
    /// the query joined `policies`. Which endpoint answered therefore decides
    /// what this returns:
    ///
    /// | Endpoint | This returns |
    /// |---|---|
    /// | [`crate::Client::get_machine`], [`crate::Client::list_machines`] | the real `policy.heartbeat_duration` |
    /// | [`crate::Client::check_out_machine`], [`crate::Client::generate_offline_proof`] | the real `policy.heartbeat_duration` |
    /// | [`crate::Client::create_machine`], [`crate::Client::ping_heartbeat`], [`crate::Client::reset_heartbeat`] | the 600s **fallback**, whatever the policy says |
    /// | [`crate::Client::update_machine`] | the 600s **fallback** — its `UPDATE … RETURNING` selects no policy column |
    ///
    /// Nothing on the response distinguishes the two, which is why this is a
    /// method on the attributes rather than a field: the caller has to know
    /// which route produced it. Reported upstream as `tamga-api-internal#7`.
    ///
    /// [`crate::Client::effective_heartbeat_window`] avoids the question
    /// entirely by reading the policy.
    pub fn observed_heartbeat_window(&self) -> Option<std::time::Duration> {
        let last = self.last_heartbeat_at?;
        let next = self.next_heartbeat_at?;
        (next - last).to_std().ok()
    }
}

/// Machine heartbeat state machine: `NotStarted` → `Alive` → `Dead` →
/// `Resurrected`.
///
/// ⚠️ **The window is policy-driven.** Server-side it is
/// `policy.heartbeat_duration`, with 600s (10 min) used only as the fallback
/// when that column is null: `effective_window_secs` prefers the policy
/// value, and the cull job's claim query selects on
/// `COALESCE(p.heartbeat_duration, 600)`. Read it with
/// [`crate::Client::effective_heartbeat_window`], which fetches the licence's
/// policy — a single call at startup, not once per tick.
///
/// It also cannot be recovered from a **write** response. The create,
/// ping-heartbeat and reset-heartbeat queries omit the policy join, so
/// `next_heartbeat_at` on those is `last_heartbeat_at + 600s` whatever the
/// policy says — never derive an interval from a ping.
///
/// The **read** paths do carry it. [`crate::Client::check_out_machine`] and
/// [`crate::Client::generate_offline_proof`] resolve the machine through a
/// policy-joined query, so on a verified machine file (see
/// [`crate::checkout::machine_file::verify_machine_file`]) or a proof
/// response, `next_heartbeat_at - last_heartbeat_at` is the real effective
/// window — the one place this crate can observe it, and only when
/// `last_heartbeat_at` is set. Otherwise learn it out of band, from whoever
/// provisions the policy, and set the interval explicitly. **On a policy with
/// a shorter window, a caller pinging on the 600s assumption pings far too
/// slowly and its machines go `Dead` on schedule.**
///
/// ⚠️ **`Dead` is a staleness report, not a tombstone.** The server computes
/// it purely from `last_heartbeat_at` versus the window and never consults
/// `policy.require_heartbeat` on the way, but the cull job that would
/// actually remove the row bails out unless `require_heartbeat` is set — and
/// that column defaults to `false`. On a default policy nothing is ever
/// culled, so a machine stays `Dead` **forever** while its row, and the seat
/// it holds against the licence, are still there.
///
/// ⚠️ **A ping, reset, create or validate response can never say `Dead`.**
/// Those four are `Dead`-free by construction: `ping-heartbeat` writes
/// `last_heartbeat_at = NOW()` and *then* derives the status from that same
/// timestamp, so its age is ~0 and the answer is always `Alive` or
/// `Resurrected`; `reset-heartbeat` nulls the column and answers
/// `NotStarted`; `POST /machines` never sets it and answers `NotStarted`. The
/// licence `validate` path never constructs
/// [`crate::models::validation::ValidationCode::HeartbeatDead`] either.
///
/// ⚠️ **The rule is not "writes cannot say `Dead`" — `PATCH /machines/{id}`
/// is a write that can.** The durable form is narrower: a response cannot say
/// `Dead` when the server derived the status from a `last_heartbeat_at`
/// *this request just wrote*. `update_machine` writes `name`, `ip`,
/// `hostname`, `platform`, `cores`, `memory`, `disk` and `metadata` and never
/// goes near the heartbeat column, so the timestamp it judges is as old as it
/// was before the call and the verdict is genuine. Stating it as write-vs-read
/// makes `update_machine` look safe to skip, which is how a `Dead` machine
/// stops being noticed on the one route an application calls routinely.
///
/// Checkout is one of the exceptions, and it is a genuine staleness verdict:
/// the server resolves the machine through a read query nobody has just
/// written to, then serializes it into the file.
/// [`crate::checkout::machine_file::verify_machine_file`] returns a
/// [`MachineResource`], so the `heartbeat_status` inside a verified
/// `.machine` file **can be `Dead`** — as can the one on the
/// [`crate::Client::generate_offline_proof`] response, which resolves the
/// same way. [`crate::Client::get_machine`] and
/// [`crate::Client::list_machines`] carry it too, and for the same reason:
/// both resolve through a policy-joined read nobody has just written to. A
/// `Dead` branch against any of those four is live code; against a ping,
/// reset or create response it is unreachable.
///
/// The scheduling rule does not depend on any of that: **never stop the ping
/// loop on a status**, whichever one comes back.
/// [`crate::Client::ping_heartbeat`] is a bare `last_heartbeat_at = NOW()`
/// write with no resurrection check, so it revives a machine that had gone
/// stale — which is why a `Dead` machine is worth pinging even though the
/// ping itself will never label it that way. The only terminal signal from a
/// ping is a `404` ([`crate::TamgaError::NotFound`]): the row is gone. Hang
/// re-activation off that, never off a status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// Never pinged.
    NotStarted,
    /// Pinged within the effective window — `policy.heartbeat_duration`,
    /// else the 600s fallback. See the type-level doc.
    Alive,
    /// Window elapsed since the last ping — and nothing more. Says nothing
    /// about whether the row still exists.
    ///
    /// Never arrives on a ping, reset or create response; it does arrive
    /// inside a verified machine file and on an offline-proof response, both
    /// of which the server builds from a read. See the type-level doc.
    Dead,
    /// Was `Dead`, but a new ping arrived within the policy's resurrection
    /// grace period — see
    /// [`crate::models::policy::HeartbeatResurrectionStrategy`].
    ///
    /// Together with `Alive` this is what [`crate::Client::ping_heartbeat`]
    /// actually returns: it is how the revival of a stale machine surfaces
    /// here, since `Dead` itself never appears on that route.
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
/// explicit delete releases it: [`crate::Client::delete_process`], or
/// [`crate::Client::delete_machine_processes`] for a machine's whole set.
/// Call one of them on shutdown — nothing else will. Keeping a PID stable
/// across restarts also bounds the damage: re-registering the same one is
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
