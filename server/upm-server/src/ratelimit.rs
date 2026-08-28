//! In-memory rate limiting (production-hardening pass).
//!
//! Two limiter instances are used (see `AppState`):
//! - a coarse **per-client** limiter applied to every request, keyed by
//!   client IP (see `client_key` in `api.rs` for how that key is derived
//!   behind a Cloudflare Tunnel);
//! - **keyed** limiters on specific security-sensitive endpoints
//!   (registration, auth challenge/verify), keyed by the identifier being
//!   targeted (username / device_id) rather than the source IP, since all
//!   traffic through a shared tunnel can otherwise look like one IP and an
//!   attacker could spread requests across many target accounts to dodge
//!   a purely IP-keyed limit.
//!
//! Implementation is a fixed-window counter: at most `limit` hits per
//! `window_secs` per key. This is intentionally simple — it's an
//! abuse-prevention guard, not a precise traffic-shaping mechanism, and a
//! fixed window is easy to reason about and cheap to run on every request.
//! Memory is bounded: once the tracked-key count crosses
//! `max_tracked_keys`, expired entries are swept before any new key is
//! admitted, and if that isn't enough to make room the check fails open
//! (allows the request) rather than let the map grow without bound — an
//! attacker cycling through unique keys to blow up memory shouldn't be
//! able to do so, and this limiter is defense in depth, not the only
//! layer (device auth still requires a valid Ed25519 signature).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

struct Window {
    window_start: u64,
    count: u32,
}

pub struct RateLimiter {
    limit: u32,
    window_secs: u64,
    max_tracked_keys: usize,
    state: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window_secs: u64) -> Self {
        RateLimiter { limit, window_secs, max_tracked_keys: 10_000, state: Mutex::new(HashMap::new()) }
    }

    /// Records one call for `key` and returns whether it's within budget
    /// for the current window. Callers should reject the request (HTTP
    /// 429) when this returns `false`.
    pub fn check(&self, key: &str) -> bool {
        let now = now_secs();
        let mut state = self.state.lock().expect("rate limiter mutex poisoned");

        if state.len() >= self.max_tracked_keys && !state.contains_key(key) {
            state.retain(|_, w| now.saturating_sub(w.window_start) < self.window_secs);
            if state.len() >= self.max_tracked_keys {
                return true; // fail open rather than grow unboundedly
            }
        }

        let entry = state.entry(key.to_string()).or_insert(Window { window_start: now, count: 0 });
        if now.saturating_sub(entry.window_start) >= self.window_secs {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count += 1;
        entry.count <= self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_blocks() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"), "4th call within the window must be blocked");
    }

    #[test]
    fn keys_are_independent() {
        let limiter = RateLimiter::new(1, 60);
        assert!(limiter.check("alice"));
        assert!(limiter.check("bob"), "a different key must have its own budget");
        assert!(!limiter.check("alice"));
    }

    #[test]
    fn window_resets_after_expiry() {
        let limiter = RateLimiter::new(1, 0); // 0-second window: every call is a new window
        assert!(limiter.check("a"));
        assert!(limiter.check("a"), "a zero-length window should reset immediately");
    }
}
