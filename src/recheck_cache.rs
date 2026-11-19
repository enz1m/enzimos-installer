// SPDX-License-Identifier: MIT
//! Reuse a successful full re-check for a short window. Long jobs re-validate their
//! inputs before every step (per overlay file, every supervision tick); repeating the
//! full scan thousands of times dominated install time on slower machines.
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(1);

pub(crate) struct Recent {
    origin: Instant,
    /// Milliseconds after `origin` of the last full check, plus one (0 = never).
    last: AtomicU64,
}

impl Recent {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
            last: AtomicU64::new(0),
        }
    }
    pub(crate) fn fresh(&self) -> bool {
        match self.last.load(Ordering::Acquire) {
            0 => false,
            at => {
                self.origin
                    .elapsed()
                    .saturating_sub(Duration::from_millis(at - 1))
                    < WINDOW
            }
        }
    }
    pub(crate) fn mark(&self) {
        self.last.store(
            self.origin.elapsed().as_millis() as u64 + 1,
            Ordering::Release,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_only_within_the_window_after_a_full_check() {
        let recent = Recent::new();
        assert!(!recent.fresh());
        recent.mark();
        assert!(recent.fresh());
        recent.last.store(1, Ordering::Release);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!recent.fresh());
    }
}
