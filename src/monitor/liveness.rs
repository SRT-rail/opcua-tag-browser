//! Telling a live session from one that stopped delivering.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Records when the server last delivered data.
///
/// A session can die on the server while the TCP connection stays up: the
/// server drops it after an outage longer than its timeout and answers every
/// later request with a fault. Nothing then reaches the subscriptions, and
/// `is_connected` keeps saying yes. This is how that state is noticed.
pub(crate) struct Liveness {
    since: Instant,
    last_ms: AtomicU64,
}

impl Liveness {
    pub(crate) fn new() -> Self {
        Self {
            since: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    /// Data arrived.
    pub(crate) fn beat(&self) {
        self.last_ms
            .store(self.since.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// How long since data last arrived.
    pub(crate) fn silent_for(&self) -> Duration {
        self.since
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last_ms.load(Ordering::Relaxed)))
    }

    /// Why the session should be replaced, if it should.
    ///
    /// Silence counts only when `watch_silence` is set, that is when the
    /// server agreed to report its clock, so that data arrives even when no
    /// tag changes.
    pub(crate) fn failure(&self, timeout: Duration, watch_silence: bool) -> Option<String> {
        let silent = self.silent_for();
        (watch_silence && silent >= timeout)
            .then(|| format!("no data from the server for {} s", silent.as_secs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_counts_only_when_the_clock_is_watched() {
        let liveness = Liveness::new();
        std::thread::sleep(Duration::from_millis(30));

        assert!(liveness.failure(Duration::from_millis(10), false).is_none());
        assert!(liveness
            .failure(Duration::from_millis(10), true)
            .is_some_and(|reason| reason.starts_with("no data from the server")));
    }

    #[test]
    fn a_beat_restarts_the_silence() {
        let liveness = Liveness::new();
        std::thread::sleep(Duration::from_millis(30));
        liveness.beat();

        assert!(liveness.silent_for() < Duration::from_millis(20));
        assert!(liveness.failure(Duration::from_millis(20), true).is_none());
    }
}
