//! In-memory wake-up bus for message waiters.
//!
//! The Turso database remains the source of truth. This module only holds
//! `watch` channels used to wake `auth.message.poll` / `auth.message.notify`
//! long-polls when a new message is queued, plus the per-target rate limit for
//! the stage-2 `agent.prompt` fallback.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, watch};

#[derive(Default)]
pub struct MailHub {
    channels: Mutex<HashMap<String, Arc<watch::Sender<u64>>>>,
    last_wakeup: Mutex<HashMap<String, u64>>,
}

impl MailHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to mail-arrival signals for one recipient.
    pub async fn subscribe(&self, jti: &str) -> watch::Receiver<u64> {
        let mut channels = self.channels.lock().await;
        let sender = channels
            .entry(jti.to_string())
            .or_insert_with(|| Arc::new(watch::channel(0).0));
        sender.subscribe()
    }

    /// Wake every waiter for a recipient.
    pub async fn notify(&self, jti: &str) {
        let channels = self.channels.lock().await;
        if let Some(sender) = channels.get(jti) {
            sender.send_modify(|value| *value = value.wrapping_add(1));
        }
    }

    /// Rate limit stage-2 prompts per target principal.
    pub async fn may_wake(&self, jti: &str, min_interval_s: u64, now: u64) -> bool {
        let last = self.last_wakeup.lock().await;
        last.get(jti)
            .is_none_or(|last| now.saturating_sub(*last) >= min_interval_s)
    }

    pub async fn mark_wake(&self, jti: &str, now: u64) {
        self.last_wakeup.lock().await.insert(jti.to_string(), now);
    }
}
