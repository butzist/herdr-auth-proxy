//! Durable state: ownership, token lineage, messages and peer grants.
//!
//! Backed by a local [Turso] database (`state.db`). The database is the source
//! of truth; the in-memory [`State`] is only a cache for the hot ownership
//! checks. A DB that cannot be opened or fails integrity checks is fatal: the
//! proxy refuses to serve rather than silently resetting authorization state.
//!
//! [Turso]: https://crates.io/crates/turso

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde_json::{Value as JsonValue, json};
use tokio::sync::Mutex;
use turso::transaction::TransactionBehavior;
use turso::{Builder, Connection};

use crate::jwt::{self, Claims, Role};
use crate::state::State;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS principals (
    jti TEXT PRIMARY KEY,
    sub TEXT NOT NULL,
    parent_jti TEXT,
    parent_sub TEXT,
    role TEXT NOT NULL,
    pane_id TEXT,
    cwd TEXT,
    workspace_id TEXT,
    exp INTEGER,
    last_seen INTEGER NOT NULL,
    last_poll INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS principals_sub ON principals(sub);
CREATE INDEX IF NOT EXISTS principals_pane ON principals(pane_id);
CREATE TABLE IF NOT EXISTS panes (
    pane_id TEXT PRIMARY KEY,
    owner_sub TEXT NOT NULL,
    owner_jti TEXT,
    tab_id TEXT,
    cwd TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tabs (
    tab_id TEXT PRIMARY KEY,
    owner_sub TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    jti TEXT PRIMARY KEY,
    sub TEXT NOT NULL,
    pane_id TEXT,
    exp INTEGER
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    thread_id TEXT,
    reply_to TEXT,
    from_sub TEXT NOT NULL,
    from_jti TEXT NOT NULL,
    to_sub TEXT NOT NULL,
    to_jti TEXT NOT NULL,
    to_pane_id TEXT,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    status TEXT NOT NULL,
    claim_id TEXT,
    claim_by TEXT,
    claim_expires_at INTEGER,
    acked_at INTEGER
);
CREATE INDEX IF NOT EXISTS messages_inbox ON messages(to_jti, status, created_at);
CREATE INDEX IF NOT EXISTS messages_thread ON messages(thread_id, created_at);
CREATE TABLE IF NOT EXISTS peer_grants (
    grant_id TEXT PRIMARY KEY,
    grantor_jti TEXT NOT NULL,
    a_jti TEXT NOT NULL,
    b_jti TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS peer_grants_a ON peer_grants(a_jti);
CREATE INDEX IF NOT EXISTS peer_grants_b ON peer_grants(b_jti);
"#;

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone)]
pub struct Principal {
    pub jti: String,
    pub sub: String,
    pub parent_jti: Option<String>,
    pub parent_sub: Option<String>,
    pub role: Role,
    pub pane_id: Option<String>,
    pub cwd: Option<String>,
    pub workspace_id: Option<String>,
    pub exp: Option<i64>,
    pub last_seen: i64,
    pub last_poll: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: String,
    pub thread_id: Option<String>,
    pub reply_to: Option<String>,
    pub from_sub: String,
    pub from_jti: String,
    pub to_sub: String,
    pub to_jti: String,
    pub to_pane_id: Option<String>,
    pub body: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub status: String,
    pub claim_id: Option<String>,
    pub claim_expires_at: Option<i64>,
    pub acked_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewMessage {
    pub to: Principal,
    pub body: String,
    pub thread_id: Option<String>,
    pub reply_to: Option<String>,
    pub expires_at: Option<i64>,
}

pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
        }
    }
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        let path = path
            .to_str()
            .ok_or_else(|| "state db path is not valid UTF-8".to_string())?;
        Self::from_builder(Builder::new_local(path)).await
    }

    pub async fn in_memory() -> Result<Self, String> {
        Self::from_builder(Builder::new_local(":memory:")).await
    }

    async fn from_builder(builder: Builder) -> Result<Self, String> {
        let db = builder.build().await.map_err(db_error)?;
        let conn = db.connect().map_err(db_error)?;
        conn.execute_batch(SCHEMA).await.map_err(db_error)?;
        conn.execute(
            "INSERT INTO schema_meta (version, created_at)
             SELECT ?1, ?2
             WHERE NOT EXISTS (SELECT 1 FROM schema_meta)",
            (SCHEMA_VERSION, now_i64()),
        )
        .await
        .map_err(db_error)?;

        let mut rows = conn
            .query("PRAGMA integrity_check", ())
            .await
            .map_err(db_error)?;
        if let Some(row) = rows.next().await.map_err(db_error)? {
            let value = row.get::<String>(0).map_err(db_error)?;
            if value != "ok" {
                return Err(format!("state db failed integrity check: {value}"));
            }
        }
        drop(rows);

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // -- ownership ---------------------------------------------------------

    pub async fn load_state(&self) -> Result<State, String> {
        let conn = self.conn.lock().await;
        let mut state = State::default();

        let mut rows = conn
            .query("SELECT pane_id, owner_sub, owner_jti, cwd FROM panes", ())
            .await
            .map_err(db_error)?;
        while let Some(row) = rows.next().await.map_err(db_error)? {
            let Some(pane_id) = text(&row, 0)? else {
                continue;
            };
            let Some(sub) = text(&row, 1)? else {
                continue;
            };
            state.panes.insert(
                pane_id,
                crate::state::Entry {
                    sub,
                    jti: text(&row, 2)?,
                    cwd: text(&row, 3)?,
                },
            );
        }

        let mut rows = conn
            .query("SELECT tab_id, owner_sub FROM tabs", ())
            .await
            .map_err(db_error)?;
        while let Some(row) = rows.next().await.map_err(db_error)? {
            let Some(tab_id) = text(&row, 0)? else {
                continue;
            };
            let Some(sub) = text(&row, 1)? else {
                continue;
            };
            state.tabs.insert(
                tab_id,
                crate::state::Entry {
                    sub,
                    jti: None,
                    cwd: None,
                },
            );
        }

        let mut rows = conn
            .query("SELECT jti, sub, pane_id, exp FROM tokens", ())
            .await
            .map_err(db_error)?;
        while let Some(row) = rows.next().await.map_err(db_error)? {
            let Some(jti) = text(&row, 0)? else {
                continue;
            };
            let Some(sub) = text(&row, 1)? else {
                continue;
            };
            state.tokens.insert(
                jti,
                crate::state::TokenEntry {
                    sub,
                    pane_id: text(&row, 2)?,
                    exp: int(&row, 3)?.map(|value| value.max(0) as u64),
                },
            );
        }
        Ok(state)
    }

    pub async fn save_token(
        &self,
        jti: &str,
        sub: &str,
        pane_id: Option<&str>,
        exp: Option<u64>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO tokens (jti, sub, pane_id, exp) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(jti) DO UPDATE SET sub = excluded.sub,
                 pane_id = excluded.pane_id, exp = excluded.exp",
            (jti, sub, pane_id, exp.map(|value| value as i64)),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn bind_token(&self, jti: &str, pane_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE tokens SET pane_id = ?1 WHERE jti = ?2",
            (pane_id, jti),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn delete_token(&self, jti: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM tokens WHERE jti = ?1", (jti,))
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn save_pane(
        &self,
        pane_id: &str,
        sub: &str,
        jti: Option<&str>,
        cwd: Option<&str>,
        tab_id: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO panes (pane_id, owner_sub, owner_jti, tab_id, cwd, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(pane_id) DO UPDATE SET owner_sub = excluded.owner_sub,
                 owner_jti = excluded.owner_jti, tab_id = excluded.tab_id,
                 cwd = excluded.cwd",
            (pane_id, sub, jti, tab_id, cwd, now_i64()),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn save_tab(&self, tab_id: &str, sub: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO tabs (tab_id, owner_sub, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(tab_id) DO UPDATE SET owner_sub = excluded.owner_sub",
            (tab_id, sub, now_i64()),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn delete_pane(&self, pane_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM panes WHERE pane_id = ?1", (pane_id,))
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn delete_tab(&self, tab_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute("DELETE FROM tabs WHERE tab_id = ?1", (tab_id,))
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn prune_tokens(&self, now: u64) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM tokens WHERE exp IS NOT NULL AND exp <= ?1",
            (now as i64,),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    /// Atomically replace the ownership/token cache in the DB. The in-memory
    /// state stays authoritative for the process; this makes it durable.
    pub async fn replace_state(&self, state: &State) -> Result<(), String> {
        let mut conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(db_error)?;
        tx.execute("DELETE FROM panes", ())
            .await
            .map_err(db_error)?;
        tx.execute("DELETE FROM tabs", ()).await.map_err(db_error)?;
        tx.execute("DELETE FROM tokens", ())
            .await
            .map_err(db_error)?;
        for (pane_id, entry) in &state.panes {
            tx.execute(
                "INSERT INTO panes (pane_id, owner_sub, owner_jti, cwd, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    pane_id.clone(),
                    entry.sub.clone(),
                    entry.jti.clone(),
                    entry.cwd.clone(),
                    now_i64(),
                ),
            )
            .await
            .map_err(db_error)?;
        }
        for (tab_id, entry) in &state.tabs {
            tx.execute(
                "INSERT INTO tabs (tab_id, owner_sub, created_at) VALUES (?1, ?2, ?3)",
                (tab_id.clone(), entry.sub.clone(), now_i64()),
            )
            .await
            .map_err(db_error)?;
        }
        for (jti, entry) in &state.tokens {
            tx.execute(
                "INSERT INTO tokens (jti, sub, pane_id, exp) VALUES (?1, ?2, ?3, ?4)",
                (
                    jti.clone(),
                    entry.sub.clone(),
                    entry.pane_id.clone(),
                    entry.exp.map(|value| value as i64),
                ),
            )
            .await
            .map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    // -- principals / lineage ---------------------------------------------

    pub async fn record_principal(
        &self,
        claims: &Claims,
        parent: Option<(&str, &str)>,
        now: u64,
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;
        let (parent_jti, parent_sub) = match parent {
            Some((jti, sub)) => (Some(jti), Some(sub)),
            None => (None, None),
        };
        conn.execute(
            "INSERT INTO principals
                 (jti, sub, parent_jti, parent_sub, role, pane_id, cwd,
                  workspace_id, exp, last_seen, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)             ON CONFLICT(jti) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 pane_id = COALESCE(excluded.pane_id, principals.pane_id),
                 exp = COALESCE(excluded.exp, principals.exp)",
            (
                claims.jti.clone(),
                claims.sub.clone(),
                parent_jti,
                parent_sub,
                claims.role.as_str(),
                claims.pane_id.clone(),
                claims.cwd.clone(),
                claims.workspace_id.clone(),
                claims.exp.map(|value| value as i64),
                now as i64,
            ),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    /// Ensure a principal row exists for an authenticated token and refresh
    /// `last_seen`. Does not clear a lineage already recorded at mint time.
    pub async fn touch_principal(&self, claims: &Claims, now: u64) -> Result<(), String> {
        let existing = self.principal_by_jti(&claims.jti).await?;
        if existing.is_none() {
            self.record_principal(claims, None, now).await?;
            return Ok(());
        }
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE principals SET last_seen = ?1,
                 pane_id = COALESCE(?2, pane_id),
                 exp = COALESCE(?3, exp)
             WHERE jti = ?4",
            (
                now as i64,
                claims.pane_id.clone(),
                claims.exp.map(|value| value as i64),
                claims.jti.clone(),
            ),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn set_principal_pane(&self, jti: &str, pane_id: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE principals SET pane_id = ?1 WHERE jti = ?2",
            (pane_id, jti),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn mark_poll(&self, jti: &str, now: u64) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE principals SET last_seen = ?1, last_poll = ?1 WHERE jti = ?2",
            (now as i64, jti),
        )
        .await
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn principal_by_jti(&self, jti: &str) -> Result<Option<Principal>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT jti, sub, parent_jti, parent_sub, role, pane_id, cwd,
                        workspace_id, exp, last_seen, last_poll, created_at
                 FROM principals WHERE jti = ?1",
                (jti,),
            )
            .await
            .map_err(db_error)?;
        match rows.next().await.map_err(db_error)? {
            Some(row) => Ok(Some(principal_from_row(&row)?)),
            None => Ok(None),
        }
    }

    pub async fn principal_by_sub(&self, sub: &str) -> Result<Option<Principal>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT jti, sub, parent_jti, parent_sub, role, pane_id, cwd,
                        workspace_id, exp, last_seen, last_poll, created_at
                 FROM principals WHERE sub = ?1
                 ORDER BY created_at DESC LIMIT 1",
                (sub,),
            )
            .await
            .map_err(db_error)?;
        match rows.next().await.map_err(db_error)? {
            Some(row) => Ok(Some(principal_from_row(&row)?)),
            None => Ok(None),
        }
    }

    pub async fn principal_by_pane(&self, pane_id: &str) -> Result<Option<Principal>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT jti, sub, parent_jti, parent_sub, role, pane_id, cwd,
                        workspace_id, exp, last_seen, last_poll, created_at
                 FROM principals WHERE pane_id = ?1
                 ORDER BY last_seen DESC LIMIT 1",
                (pane_id,),
            )
            .await
            .map_err(db_error)?;
        match rows.next().await.map_err(db_error)? {
            Some(row) => Ok(Some(principal_from_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Resolve a `to` value: jti, sub, pane id, or `parent`.
    pub async fn resolve_recipient(
        &self,
        caller: &Principal,
        to: &str,
    ) -> Result<Option<Principal>, String> {
        if to == "parent" {
            return match &caller.parent_jti {
                Some(jti) => self.principal_by_jti(jti).await,
                None => Ok(None),
            };
        }
        if let Some(principal) = self.principal_by_jti(to).await? {
            return Ok(Some(principal));
        }
        if let Some(principal) = self.principal_by_sub(to).await? {
            return Ok(Some(principal));
        }
        self.principal_by_pane(to).await
    }

    pub async fn can_message(
        &self,
        caller: &Principal,
        target: &Principal,
        now: u64,
    ) -> Result<bool, String> {
        if caller.jti == target.jti {
            return Ok(false);
        }
        if caller.role == Role::Admin {
            return Ok(true);
        }
        if target.parent_jti.as_deref() == Some(caller.jti.as_str())
            || caller.parent_jti.as_deref() == Some(target.jti.as_str())
        {
            return Ok(true);
        }
        self.has_peer_grant(&caller.jti, &target.jti, now).await
    }

    // -- messages ----------------------------------------------------------

    pub async fn send(
        &self,
        from: &Principal,
        message: &NewMessage,
        now: u64,
    ) -> Result<String, String> {
        let id = format!("m_{}", jwt::random_id());
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO messages
                 (id, thread_id, reply_to, from_sub, from_jti, to_sub, to_jti,
                  to_pane_id, body, created_at, expires_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending')",
            (
                id.clone(),
                message.thread_id.clone(),
                message.reply_to.clone(),
                from.sub.clone(),
                from.jti.clone(),
                message.to.sub.clone(),
                message.to.jti.clone(),
                message.to.pane_id.clone(),
                message.body.clone(),
                now as i64,
                message.expires_at,
            ),
        )
        .await
        .map_err(db_error)?;
        Ok(id)
    }

    /// Atomically claim deliverable messages. Unacked claims whose lease
    /// expired are claimed again.
    pub async fn claim(
        &self,
        jti: &str,
        limit: usize,
        lease_s: u64,
        now: u64,
    ) -> Result<Vec<Message>, String> {
        let mut conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await
            .map_err(db_error)?;

        let mut rows = tx
            .query(
                "SELECT id FROM messages
                 WHERE to_jti = ?1
                   AND ((status = 'pending' AND (expires_at IS NULL OR expires_at > ?2))
                        OR (status = 'claimed' AND claim_expires_at <= ?2))
                 ORDER BY created_at ASC LIMIT ?3",
                (jti, now as i64, limit as i64),
            )
            .await
            .map_err(db_error)?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await.map_err(db_error)? {
            ids.push(row.get::<String>(0).map_err(db_error)?);
        }
        drop(rows);

        let claim_id = format!("c_{}", jwt::random_id());
        let expires = (now + lease_s) as i64;
        for id in &ids {
            tx.execute(
                "UPDATE messages SET status = 'claimed', claim_id = ?1,
                     claim_by = ?2, claim_expires_at = ?3
                 WHERE id = ?4",
                (claim_id.clone(), jti, expires, id.clone()),
            )
            .await
            .map_err(db_error)?;
        }
        tx.commit().await.map_err(db_error)?;
        drop(conn);

        let mut messages = Vec::new();
        for id in ids {
            if let Some(message) = self.message_by_id(&id).await? {
                messages.push(message);
            }
        }
        Ok(messages)
    }

    pub async fn ack(
        &self,
        jti: &str,
        ids: &[String],
        claim_id: &str,
        now: u64,
    ) -> Result<u64, String> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().await;
        let mut acked = 0u64;
        for id in ids {
            acked += conn
                .execute(
                    "UPDATE messages SET status = 'acked', acked_at = ?1
                     WHERE id = ?2 AND to_jti = ?3 AND claim_id = ?4
                       AND status = 'claimed'",
                    (now as i64, id.clone(), jti, claim_id),
                )
                .await
                .map_err(db_error)?;
        }
        Ok(acked)
    }

    pub async fn pending_for(&self, jti: &str, now: u64) -> Result<Vec<Message>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT id, thread_id, reply_to, from_sub, from_jti, to_sub,
                        to_jti, to_pane_id, body, created_at, expires_at, status,
                        claim_id, claim_expires_at, acked_at
                 FROM messages
                 WHERE to_jti = ?1
                   AND ((status = 'pending' AND (expires_at IS NULL OR expires_at > ?2))
                        OR (status = 'claimed' AND claim_expires_at <= ?2))
                 ORDER BY created_at ASC",
                (jti, now as i64),
            )
            .await
            .map_err(db_error)?;
        let mut messages = Vec::new();
        while let Some(row) = rows.next().await.map_err(db_error)? {
            messages.push(message_from_row(&row)?);
        }
        Ok(messages)
    }

    pub async fn message_by_id(&self, id: &str) -> Result<Option<Message>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT id, thread_id, reply_to, from_sub, from_jti, to_sub,
                        to_jti, to_pane_id, body, created_at, expires_at, status,
                        claim_id, claim_expires_at, acked_at
                 FROM messages WHERE id = ?1",
                (id,),
            )
            .await
            .map_err(db_error)?;
        match rows.next().await.map_err(db_error)? {
            Some(row) => Ok(Some(message_from_row(&row)?)),
            None => Ok(None),
        }
    }

    pub async fn counts_for(&self, jti: &str, now: u64) -> Result<HashMap<String, i64>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT status, COUNT(*) FROM messages
                 WHERE to_jti = ?1 AND (expires_at IS NULL OR expires_at > ?2)
                 GROUP BY status",
                (jti, now as i64),
            )
            .await
            .map_err(db_error)?;
        let mut counts = HashMap::new();
        while let Some(row) = rows.next().await.map_err(db_error)? {
            let status = row.get::<String>(0).map_err(db_error)?;
            let count = row.get::<i64>(1).map_err(db_error)?;
            counts.insert(status, count);
        }
        Ok(counts)
    }

    // -- peer grants -------------------------------------------------------

    pub async fn grant_peer(
        &self,
        grantor_jti: &str,
        a_jti: &str,
        b_jti: &str,
        expires_at: Option<i64>,
        now: u64,
    ) -> Result<String, String> {
        let grant_id = format!("g_{}", jwt::random_id());
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO peer_grants
                 (grant_id, grantor_jti, a_jti, b_jti, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                grant_id.clone(),
                grantor_jti,
                a_jti,
                b_jti,
                now as i64,
                expires_at,
            ),
        )
        .await
        .map_err(db_error)?;
        Ok(grant_id)
    }

    pub async fn revoke_peer(
        &self,
        grantor_jti: &str,
        grant_id: &str,
        now: u64,
    ) -> Result<bool, String> {
        let conn = self.conn.lock().await;
        let changed = conn
            .execute(
                "UPDATE peer_grants SET revoked_at = ?1
                 WHERE grant_id = ?2 AND grantor_jti = ?3 AND revoked_at IS NULL",
                (now as i64, grant_id, grantor_jti),
            )
            .await
            .map_err(db_error)?;
        Ok(changed > 0)
    }

    pub async fn list_peers(&self, grantor_jti: &str) -> Result<Vec<JsonValue>, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT grant_id, a_jti, b_jti, created_at, expires_at, revoked_at
                 FROM peer_grants WHERE grantor_jti = ?1
                 ORDER BY created_at DESC",
                (grantor_jti,),
            )
            .await
            .map_err(db_error)?;
        let mut grants = Vec::new();
        while let Some(row) = rows.next().await.map_err(db_error)? {
            grants.push(json!({
                "grant_id": row.get::<String>(0).map_err(db_error)?,
                "a_jti": row.get::<String>(1).map_err(db_error)?,
                "b_jti": row.get::<String>(2).map_err(db_error)?,
                "created_at": row.get::<i64>(3).map_err(db_error)?,
                "expires_at": int(&row, 4)?,
                "revoked_at": int(&row, 5)?,
            }));
        }
        Ok(grants)
    }

    pub async fn has_peer_grant(&self, a_jti: &str, b_jti: &str, now: u64) -> Result<bool, String> {
        let conn = self.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT 1 FROM peer_grants
                 WHERE revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > ?1)
                   AND ((a_jti = ?2 AND b_jti = ?3) OR (a_jti = ?3 AND b_jti = ?2))
                 LIMIT 1",
                (now as i64, a_jti, b_jti),
            )
            .await
            .map_err(db_error)?;
        Ok(rows.next().await.map_err(db_error)?.is_some())
    }
}

fn now_i64() -> i64 {
    jwt::now() as i64
}

fn db_error(error: turso::Error) -> String {
    format!("state db: {error}")
}

fn text(row: &turso::Row, idx: usize) -> Result<Option<String>, String> {
    match row.get_value(idx).map_err(db_error)? {
        turso::Value::Text(value) => Ok(Some(value)),
        turso::Value::Null => Ok(None),
        other => Err(format!("state db: expected text, got {other:?}")),
    }
}

fn int(row: &turso::Row, idx: usize) -> Result<Option<i64>, String> {
    match row.get_value(idx).map_err(db_error)? {
        turso::Value::Integer(value) => Ok(Some(value)),
        turso::Value::Null => Ok(None),
        other => Err(format!("state db: expected integer, got {other:?}")),
    }
}

fn required_text(row: &turso::Row, idx: usize) -> Result<String, String> {
    text(row, idx)?.ok_or_else(|| "state db: unexpected NULL".to_string())
}

fn principal_from_row(row: &turso::Row) -> Result<Principal, String> {
    let role = match required_text(row, 4)?.as_str() {
        "agent" => Role::Agent,
        "orchestrator" => Role::Orchestrator,
        "admin" => Role::Admin,
        other => return Err(format!("state db: unknown role {other}")),
    };
    Ok(Principal {
        jti: required_text(row, 0)?,
        sub: required_text(row, 1)?,
        parent_jti: text(row, 2)?,
        parent_sub: text(row, 3)?,
        role,
        pane_id: text(row, 5)?,
        cwd: text(row, 6)?,
        workspace_id: text(row, 7)?,
        exp: int(row, 8)?,
        last_seen: int(row, 9)?.unwrap_or_default(),
        last_poll: int(row, 10)?,
        created_at: int(row, 11)?.unwrap_or_default(),
    })
}

fn message_from_row(row: &turso::Row) -> Result<Message, String> {
    Ok(Message {
        id: required_text(row, 0)?,
        thread_id: text(row, 1)?,
        reply_to: text(row, 2)?,
        from_sub: required_text(row, 3)?,
        from_jti: required_text(row, 4)?,
        to_sub: required_text(row, 5)?,
        to_jti: required_text(row, 6)?,
        to_pane_id: text(row, 7)?,
        body: required_text(row, 8)?,
        created_at: int(row, 9)?.unwrap_or_default(),
        expires_at: int(row, 10)?,
        status: required_text(row, 11)?,
        claim_id: text(row, 12)?,
        claim_expires_at: int(row, 13)?,
        acked_at: int(row, 14)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(jti: &str, sub: &str) -> Claims {
        Claims {
            iss: crate::jwt::ISS.into(),
            sub: sub.into(),
            jti: jti.into(),
            iat: jwt::now(),
            nbf: jwt::now(),
            exp: None,
            role: Role::Agent,
            pane_id: None,
            cwd: None,
            workspace_id: None,
            grants: Vec::new(),
            perm: None,
        }
    }

    #[tokio::test]
    async fn file_db_survives_reopen() {
        let path = std::env::temp_dir().join(format!("hap-store-{}", jwt::random_id()));
        {
            let store = Store::open(&path).await.unwrap();
            store
                .save_token("j1", "orch", None, Some(42))
                .await
                .unwrap();
            store
                .save_pane("w1:p1", "orch", Some("j1"), Some("/w"), None)
                .await
                .unwrap();
        }
        let store = Store::open(&path).await.unwrap();
        let state = store.load_state().await.unwrap();
        assert!(state.owns_pane("w1:p1", "orch"));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("db-wal")).ok();
        std::fs::remove_file(path.with_extension("db-shm")).ok();
    }

    #[tokio::test]
    async fn corrupt_db_fails_closed() {
        let path = std::env::temp_dir().join(format!("hap-corrupt-{}", jwt::random_id()));
        std::fs::write(&path, b"this is not a sqlite database").unwrap();
        assert!(Store::open(&path).await.is_err());
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn schema_and_ownership_roundtrip() {
        let store = Store::in_memory().await.unwrap();
        store
            .save_token("j1", "orch", None, Some(42))
            .await
            .unwrap();
        store.bind_token("j1", "w1:p1").await.unwrap();
        store
            .save_pane("w1:p1", "orch", Some("j1"), Some("/w"), None)
            .await
            .unwrap();
        store.save_tab("w1:t1", "orch").await.unwrap();

        let state = store.load_state().await.unwrap();
        assert!(state.owns_pane("w1:p1", "orch"));
        assert!(state.owns_tab("w1:t1", "orch"));
        assert_eq!(state.pane_of_token("j1").as_deref(), Some("w1:p1"));

        store.delete_pane("w1:p1").await.unwrap();
        store.delete_tab("w1:t1").await.unwrap();
        store.delete_token("j1").await.unwrap();
        let state = store.load_state().await.unwrap();
        assert!(state.panes.is_empty());
        assert!(state.tabs.is_empty());
        assert!(state.tokens.is_empty());
    }

    #[tokio::test]
    async fn parent_and_child_can_exchange_messages() {
        let store = Store::in_memory().await.unwrap();
        let now = jwt::now();
        let parent = claims("parent", "orch");
        let child = claims("child", "orch:child");
        store.record_principal(&parent, None, now).await.unwrap();
        store
            .record_principal(&child, Some(("parent", "orch")), now)
            .await
            .unwrap();
        let parent = store.principal_by_jti("parent").await.unwrap().unwrap();
        let child = store.principal_by_jti("child").await.unwrap().unwrap();
        assert!(store.can_message(&parent, &child, now).await.unwrap());
        assert!(store.can_message(&child, &parent, now).await.unwrap());

        let id = store
            .send(
                &parent,
                &NewMessage {
                    to: child.clone(),
                    body: "hello".into(),
                    thread_id: Some("t".into()),
                    reply_to: None,
                    expires_at: None,
                },
                now,
            )
            .await
            .unwrap();
        let claimed = store.claim("child", 10, 30, now).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, id);
        let acked = store
            .ack("child", &[id], claimed[0].claim_id.as_deref().unwrap(), now)
            .await
            .unwrap();
        assert_eq!(acked, 1);
        assert!(store.pending_for("child", now).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn siblings_need_a_grant_and_revocation_is_immediate() {
        let store = Store::in_memory().await.unwrap();
        let now = jwt::now();
        store
            .record_principal(&claims("p", "orch"), None, now)
            .await
            .unwrap();
        store
            .record_principal(&claims("a", "orch:a"), Some(("p", "orch")), now)
            .await
            .unwrap();
        store
            .record_principal(&claims("b", "orch:b"), Some(("p", "orch")), now)
            .await
            .unwrap();
        let a = store.principal_by_jti("a").await.unwrap().unwrap();
        let b = store.principal_by_jti("b").await.unwrap().unwrap();
        assert!(!store.can_message(&a, &b, now).await.unwrap());
        let grant = store.grant_peer("p", "a", "b", None, now).await.unwrap();
        assert!(store.can_message(&a, &b, now).await.unwrap());
        assert!(store.can_message(&b, &a, now).await.unwrap());
        assert!(store.revoke_peer("p", &grant, now + 1).await.unwrap());
        assert!(!store.can_message(&a, &b, now + 1).await.unwrap());
    }

    #[tokio::test]
    async fn ack_requires_the_matching_claim() {
        let store = Store::in_memory().await.unwrap();
        let now = jwt::now();
        store
            .record_principal(&claims("p", "orch"), None, now)
            .await
            .unwrap();
        store
            .record_principal(&claims("c", "orch:c"), Some(("p", "orch")), now)
            .await
            .unwrap();
        let p = store.principal_by_jti("p").await.unwrap().unwrap();
        let c = store.principal_by_jti("c").await.unwrap().unwrap();
        let id = store
            .send(
                &p,
                &NewMessage {
                    to: c,
                    body: "x".into(),
                    thread_id: None,
                    reply_to: None,
                    expires_at: None,
                },
                now,
            )
            .await
            .unwrap();
        let _claimed = store.claim("c", 1, 1, now).await.unwrap();
        assert_eq!(
            store
                .ack("c", std::slice::from_ref(&id), "wrong", now)
                .await
                .unwrap(),
            0
        );
        // Lease expiry makes the unacked message deliverable again.
        let reclaimed = store.claim("c", 1, 1, now + 5).await.unwrap();
        assert_eq!(reclaimed.len(), 1);
        let claim = reclaimed[0].claim_id.clone().unwrap();
        assert_eq!(store.ack("c", &[id], &claim, now + 6).await.unwrap(), 1);
    }
}
