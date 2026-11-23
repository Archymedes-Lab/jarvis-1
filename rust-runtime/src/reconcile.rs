//! Cross-view reconciliation for the Rust hot path.
//!
//! Python owns policy and incidents; this crate owns high-volume identity,
//! state maintenance, and the per-instance verdict. It mirrors
//! `jarvis/core/execution/presence.py`: confidence over six independent
//! views, never a bare boolean. Kernel callbacks are one view among six,
//! never absolute truth.

/// One process instance across independent boolean views.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Presence {
    pub kernel_create: bool,
    pub kernel_exit: bool,
    pub etw_start: bool,
    pub etw_stop: bool,
    pub sysmon_create: bool,
    pub snapshot: bool,
    pub thread_activity: bool,
    pub image_activity: bool,
    pub cpu_activity: bool,
    pub network_activity: bool,
}

/// Verdicts mirror the Python engine so significant evidence crosses the
/// boundary with identical names.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    VerifiedProcess,
    VerifiedExit,
    CrossViewMismatch,
    UnexplainedProcess,
    Exited,
    Unknown,
}

impl Presence {
    fn created(&self) -> bool {
        self.kernel_create || self.etw_start || self.sysmon_create
    }

    fn exited(&self) -> bool {
        self.kernel_exit || self.etw_stop
    }

    fn active(&self) -> bool {
        self.thread_activity
            || self.image_activity
            || self.cpu_activity
            || self.network_activity
    }

    /// Visibility confidence over six independent views.
    pub fn confidence(&self) -> f64 {
        let present = [
            self.kernel_create,
            self.etw_start,
            self.sysmon_create,
            self.snapshot,
            self.thread_activity,
            self.image_activity,
        ]
        .iter()
        .filter(|v| **v)
        .count() as f64
            / 6.0;
        if self.exited()
            && !self.snapshot
            && !self.thread_activity
            && !self.cpu_activity
            && !self.network_activity
        {
            present.min(0.3)
        } else if self.exited() {
            present.min(0.6)
        } else {
            present
        }
    }

    /// Reconcile one instance. `coverage_valid` means the stream was in a
    /// position to contradict the snapshot; when false, absence proves
    /// nothing and the answer is Unknown.
    pub fn reconcile(&self, coverage_valid: bool) -> Verdict {
        let created = self.created();
        let active = self.active();
        if self.exited() && (self.snapshot || active) {
            return if coverage_valid {
                Verdict::CrossViewMismatch
            } else {
                Verdict::Unknown
            };
        }
        if created && self.snapshot {
            return Verdict::VerifiedProcess;
        }
        if self.exited() && !self.snapshot && !active {
            return Verdict::VerifiedExit;
        }
        if created && !self.snapshot && active {
            return if coverage_valid {
                Verdict::CrossViewMismatch
            } else {
                Verdict::Unknown
            };
        }
        if created && !self.snapshot && !active {
            return if coverage_valid {
                Verdict::Exited
            } else {
                Verdict::Unknown
            };
        }
        if self.snapshot && !created {
            if !coverage_valid {
                return Verdict::Unknown;
            }
            return Verdict::UnexplainedProcess;
        }
        Verdict::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified() -> Presence {
        Presence {
            kernel_create: true,
            etw_start: true,
            sysmon_create: true,
            snapshot: true,
            thread_activity: true,
            image_activity: true,
            cpu_activity: true,
            network_activity: true,
            ..Default::default()
        }
    }

    #[test]
    fn verified_process_needs_creation_and_snapshot() {
        assert_eq!(verified().reconcile(true), Verdict::VerifiedProcess);
        assert!(verified().confidence() >= 0.85);
    }

    #[test]
    fn threads_without_snapshot_are_a_mismatch() {
        let p = Presence {
            kernel_create: true,
            etw_start: true,
            thread_activity: true,
            ..Default::default()
        };
        assert_eq!(p.reconcile(true), Verdict::CrossViewMismatch);
    }

    #[test]
    fn gapped_coverage_never_confirms_hiding() {
        let p = Presence {
            snapshot: true,
            ..Default::default()
        };
        assert_eq!(p.reconcile(false), Verdict::Unknown);
    }

    #[test]
    fn clean_exit_is_not_a_mismatch() {
        let p = Presence {
            kernel_create: true,
            kernel_exit: true,
            etw_start: true,
            etw_stop: true,
            ..Default::default()
        };
        assert_eq!(p.reconcile(true), Verdict::VerifiedExit);
    }

    #[test]
    fn exit_with_snapshot_is_contradiction_only_under_continuous_coverage() {
        let p = Presence {
            kernel_create: true,
            kernel_exit: true,
            snapshot: true,
            ..Default::default()
        };
        assert_eq!(p.reconcile(true), Verdict::CrossViewMismatch);
        assert_eq!(p.reconcile(false), Verdict::Unknown);
    }

    #[test]
    fn interrupted_stream_does_not_assert_activity_mismatch_or_exit() {
        let p = Presence {
            etw_start: true,
            cpu_activity: true,
            ..Default::default()
        };
        assert_eq!(p.reconcile(false), Verdict::Unknown);
        let quiet = Presence { cpu_activity: false, ..p };
        assert_eq!(quiet.reconcile(false), Verdict::Unknown);
    }
}
