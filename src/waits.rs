//! In-memory wait and watch state for the proxy.
//!
//! `WaitHub` tracks blocking proxy calls (`auth.message.poll` and the composite
//! `poll` MCP tool). Orchestrators use it to tell a parked agent (`waiting`)
//! apart from a busy one, because herdr's own lifecycle has no such state.
//!
//! `WatchHub` stores non-blocking lifecycle watches. The proxy monitors owned
//! children in the background and wakes an idle waiter with a fixed prompt, so
//! an orchestrator never has to park inside a tool call.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use serde_json::{Value, json};

use crate::jwt;

/// Kinds accepted by `auth.wait.begin` / tracked internally.
pub const WAIT_KINDS: &[&str] = &["poll", "message-poll", "watch", "agent-wait", "pane-wait"];

/// Statuses a watch may trigger on. `killed` means the target disappeared.
pub const WATCH_STATUSES: &[&str] = &["idle", "working", "blocked", "done", "unknown", "killed"];

pub const WATCH_DEFAULT_TTL_S: u64 = 600;
pub const WATCH_MAX_TTL_S: u64 = 3600;

/// TTL for a wait record. A recorded wait is diagnostic state only; it is
/// replaced on the next begin and pruned once it expires.
pub fn wait_ttl_s(wait_ms: u64) -> u64 {
    if wait_ms == 0 {
        86_400
    } else {
        wait_ms / 1_000 + 120
    }
}

#[derive(Debug, Clone)]
pub struct WaitInfo {
    pub wait_id: String,
    pub sub: String,
    pub jti: String,
    pub pane_id: Option<String>,
    pub kind: String,
    pub since: u64,
    pub expires_at: u64,
}

impl WaitInfo {
    pub fn to_json(&self) -> Value {
        json!({
            "wait_id": self.wait_id,
            "sub": self.sub,
            "jti": self.jti,
            "pane_id": self.pane_id,
            "kind": self.kind,
            "since": self.since,
            "expires_at": self.expires_at,
        })
    }
}

#[derive(Default)]
pub struct WaitHub {
    waits: Mutex<HashMap<String, WaitInfo>>,
}

impl WaitHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a wait, replacing any previous wait for the same principal.
    pub fn begin(
        &self,
        sub: &str,
        jti: &str,
        pane_id: Option<&str>,
        kind: &str,
        ttl_s: u64,
    ) -> String {
        let now = jwt::now();
        let wait_id = format!("w-{}", jwt::random_id());
        let info = WaitInfo {
            wait_id: wait_id.clone(),
            sub: sub.to_string(),
            jti: jti.to_string(),
            pane_id: pane_id.map(str::to_owned),
            kind: kind.to_string(),
            since: now,
            expires_at: now.saturating_add(ttl_s.max(1)),
        };
        if let Ok(mut waits) = self.waits.lock() {
            waits.retain(|_, wait| wait.expires_at > now);
            waits.insert(jti.to_string(), info);
        }
        wait_id
    }

    /// Record a wait only if the principal has none. Used by the inner
    /// `message.poll` calls of the composite `poll` tool so the outer wait kind
    /// is not overwritten.
    pub fn begin_if_absent(
        &self,
        sub: &str,
        jti: &str,
        pane_id: Option<&str>,
        kind: &str,
        ttl_s: u64,
    ) -> Option<String> {
        let now = jwt::now();
        let mut waits = self.waits.lock().ok()?;
        waits.retain(|_, wait| wait.expires_at > now);
        if waits.contains_key(jti) {
            return None;
        }
        let wait_id = format!("w-{}", jwt::random_id());
        waits.insert(
            jti.to_string(),
            WaitInfo {
                wait_id: wait_id.clone(),
                sub: sub.to_string(),
                jti: jti.to_string(),
                pane_id: pane_id.map(str::to_owned),
                kind: kind.to_string(),
                since: now,
                expires_at: now.saturating_add(ttl_s.max(1)),
            },
        );
        Some(wait_id)
    }

    pub fn end(&self, jti: &str, wait_id: &str) -> bool {
        let Ok(mut waits) = self.waits.lock() else {
            return false;
        };
        if waits.get(jti).is_some_and(|wait| wait.wait_id == wait_id) {
            waits.remove(jti);
            true
        } else {
            false
        }
    }

    pub fn list(&self, now: u64) -> Vec<WaitInfo> {
        let Ok(mut waits) = self.waits.lock() else {
            return Vec::new();
        };
        waits.retain(|_, wait| wait.expires_at > now);
        let mut waits: Vec<WaitInfo> = waits.values().cloned().collect();
        waits.sort_by_key(|wait| wait.since);
        waits
    }
}

/// Removes a wait when the blocking call returns, unless another outer wait
/// already owned the principal's entry.
pub struct WaitGuard {
    hub: std::sync::Arc<WaitHub>,
    jti: String,
    wait_id: Option<String>,
}

impl WaitGuard {
    pub fn new(hub: std::sync::Arc<WaitHub>, jti: &str, wait_id: Option<String>) -> Self {
        Self {
            hub,
            jti: jti.to_string(),
            wait_id,
        }
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        if let Some(wait_id) = &self.wait_id {
            self.hub.end(&self.jti, wait_id);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Watch {
    pub watch_id: String,
    pub sub: String,
    pub jti: String,
    /// Pane of the agent that receives the wake-up prompt.
    pub pane_id: String,
    /// Watched pane ids.
    pub targets: Vec<String>,
    /// Empty means any change.
    pub until: Vec<String>,
    /// Last observed status per target; also the diff baseline.
    pub initial: BTreeMap<String, String>,
    /// Changes accumulated since the last drain.
    pub changes: Vec<Value>,
    /// Last time a wake-up prompt was delivered.
    pub last_prompt: Option<u64>,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Watch {
    pub fn statuses(&self) -> BTreeMap<String, String> {
        self.initial.clone()
    }
}

#[derive(Default)]
pub struct WatchHub {
    watches: Mutex<HashMap<String, Watch>>,
}

impl WatchHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, watch: Watch) {
        if let Ok(mut watches) = self.watches.lock() {
            watches.insert(watch.watch_id.clone(), watch);
        }
    }

    pub fn remove(&self, sub: &str, watch_id: &str) -> bool {
        let Ok(mut watches) = self.watches.lock() else {
            return false;
        };
        if watches.get(watch_id).is_some_and(|watch| watch.sub == sub) {
            watches.remove(watch_id);
            true
        } else {
            false
        }
    }

    pub fn is_empty(&self) -> bool {
        self.watches
            .lock()
            .map(|watches| watches.is_empty())
            .unwrap_or(true)
    }

    pub fn list(&self, now: u64) -> Vec<Watch> {
        let Ok(mut watches) = self.watches.lock() else {
            return Vec::new();
        };
        watches.retain(|_, watch| watch.expires_at > now);
        let mut watches: Vec<Watch> = watches.values().cloned().collect();
        watches.sort_by_key(|watch| watch.created_at);
        watches
    }

    /// Append trigger changes, advance the diff baseline, and report whether
    /// the watch received new changes.
    pub fn record(
        &self,
        watch_id: &str,
        mut changes: Vec<Value>,
        statuses: BTreeMap<String, String>,
    ) -> bool {
        let Ok(mut watches) = self.watches.lock() else {
            return false;
        };
        let Some(watch) = watches.get_mut(watch_id) else {
            return false;
        };
        watch.initial = statuses;
        if changes.is_empty() {
            return false;
        }
        watch.changes.append(&mut changes);
        true
    }

    pub fn has_pending(&self, watch_id: &str) -> bool {
        self.watches
            .lock()
            .ok()
            .and_then(|watches| watches.get(watch_id).map(|watch| !watch.changes.is_empty()))
            .unwrap_or(false)
    }

    pub fn mark_prompt(&self, watch_id: &str, now: u64) {
        if let Ok(mut watches) = self.watches.lock()
            && let Some(watch) = watches.get_mut(watch_id)
        {
            watch.last_prompt = Some(now);
        }
    }

    /// Remove and return fired watches owned by `sub`.
    pub fn take_fired(&self, sub: &str) -> Vec<Watch> {
        let Ok(mut watches) = self.watches.lock() else {
            return Vec::new();
        };
        let ids: Vec<String> = watches
            .values()
            .filter(|watch| watch.sub == sub && !watch.changes.is_empty())
            .map(|watch| watch.watch_id.clone())
            .collect();
        ids.into_iter()
            .filter_map(|id| watches.remove(&id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_lifecycle_and_replacement() {
        let hub = WaitHub::new();
        let first = hub.begin("orch", "j1", Some("w1:p1"), "poll", 60);
        assert!(hub.end("j1", &first));
        assert!(!hub.end("j1", &first));

        let second = hub.begin("orch", "j1", Some("w1:p1"), "message-poll", 60);
        assert!(!hub.end("j2", &second));
        assert!(hub.end("j1", &second));

        let outer = hub.begin("orch", "j1", None, "poll", 60);
        assert!(
            hub.begin_if_absent("orch", "j1", None, "message-poll", 60)
                .is_none()
        );
        assert!(hub.end("j1", &outer));
        assert!(
            hub.begin_if_absent("orch", "j1", None, "message-poll", 60)
                .is_some()
        );
    }

    #[test]
    fn expired_waits_are_pruned() {
        let hub = WaitHub::new();
        hub.begin("orch", "j1", None, "poll", 1);
        assert!(hub.list(jwt::now() + 5).is_empty());
    }

    #[test]
    fn fired_watches_drain_once_per_owner() {
        let hub = WatchHub::new();
        let now = jwt::now();
        hub.insert(Watch {
            watch_id: "watch-1".into(),
            sub: "orch".into(),
            jti: "j1".into(),
            pane_id: "w1:p0".into(),
            targets: vec!["w1:p1".into()],
            until: Vec::new(),
            initial: BTreeMap::from([("w1:p1".into(), "working".into())]),
            changes: Vec::new(),
            last_prompt: None,
            created_at: now,
            expires_at: now + 60,
        });
        assert!(hub.record(
            "watch-1",
            vec![json!({"target": "worker", "from": "working", "to": "idle"})],
            BTreeMap::from([("w1:p1".into(), "idle".into())]),
        ));
        // Recording again with no changes must not duplicate.
        assert!(!hub.record(
            "watch-1",
            Vec::new(),
            BTreeMap::from([("w1:p1".into(), "idle".into())]),
        ));
        let fired = hub.take_fired("orch");
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].changes.len(), 1);
        assert!(hub.take_fired("orch").is_empty());
        assert!(hub.is_empty());
    }

    #[test]
    fn watch_removal_is_owner_scoped() {
        let hub = WatchHub::new();
        let now = jwt::now();
        hub.insert(Watch {
            watch_id: "watch-1".into(),
            sub: "orch".into(),
            jti: "j1".into(),
            pane_id: "w1:p0".into(),
            targets: Vec::new(),
            until: Vec::new(),
            initial: BTreeMap::new(),
            changes: Vec::new(),
            last_prompt: None,
            created_at: now,
            expires_at: now + 60,
        });
        assert!(!hub.remove("other", "watch-1"));
        assert!(hub.remove("orch", "watch-1"));
    }
}
