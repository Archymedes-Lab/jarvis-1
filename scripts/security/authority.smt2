; Response-authority SPECIFICATION, not a refinement proof of defense.py.
; Assumptions: trustworthy flags, evidence, identities and human approval;
; atomic application; no crash, concurrency, journal or expiry behavior modeled.
(set-logic QF_LIA)
(set-option :timeout 5000)
(declare-const approved Bool)
(declare-const autonomous Bool)
(declare-const action-enabled Bool)
(declare-const severe Bool)
(declare-const complete-evidence Bool)
(declare-const human-undone Bool)
(declare-const active Int)
(declare-const cap Int)
; Auto must preserve human undo, complete evidence and finite action cap.
(define-fun auto-ok () Bool
  (and autonomous action-enabled severe complete-evidence
       (not human-undone) (>= active 0) (> cap 0) (< active cap)))
(define-fun may-apply () Bool (or approved auto-ok))
(push)
; No unapproved action can bypass any automatic condition.
(assert (and may-apply (not approved)
  (or (not autonomous) (not action-enabled) (not severe)
      (not complete-evidence) human-undone (< active 0) (<= cap 0) (>= active cap))))
(check-sat)
(pop)
; Negative control: the stronger claim "no human override of automatic flags"
; is false. A solver that always says UNSAT must fail the adapter.
(assert (and may-apply approved (not autonomous)))
(check-sat)
