"""`jarvis defend` and `jarvis answer` — the autonomous-response controls.

    jarvis defend                 what JARVIS did, and what is waiting for you
    jarvis defend approve <id>    run a proposed containment action now
    jarvis defend undo <id>       reverse an action JARVIS took
    jarvis defend actions         the actions available and whether they are on
    jarvis defend reconcile       read-only recovery check for interrupted actions
    jarvis answer <id> yes|no     answer a proactive question

Turning automatic response on is a config change (autonomous_defense plus the
per-action flags in ~/.jarvis/config.json); this command never edits config,
so nothing starts acting on its own without an explicit edit.
"""


from jarvis.core.util import iso
from jarvis.response import acknowledge, alert, defense, questions
from jarvis.response.actions import base

from ..output import color, is_tty, typed_confirmation


def cmd_defend(store, args):
    t = is_tty()
    sub = args.action_arg

    if sub == "approve":
        ok, detail = defense.approve(store, args.id)
        print(("approved: " if ok else "not approved: ") + detail)
        return 0 if ok else 1
    if sub == "undo":
        ok, detail = defense.undo(store, args.id)
        print(("undone: " if ok else "could not undo: ") + detail)
        return 0 if ok else 1
    if sub == "actions":
        conf = alert.load_conf()
        on = conf.get("autonomous_defense", False) is True
        print(f"autonomous response: {'ON' if on else 'OFF'} "
              f"(set autonomous_defense in ~/.jarvis/config.json)")
        for a in base.registry().values():
            enabled = on and a.enable_flag and conf.get(a.enable_flag, False) is True
            mark = color("auto", "ok", t) if enabled else "propose-only"
            print(f"  {a.id:18} [{a.host}] {a.title} — {mark}"
                  + (f"  (enable: {a.enable_flag}=true)" if a.enable_flag else ""))
        return 0
    if sub == "reconcile":
        rows = defense.reconcile(store)
        if not rows:
            print("no interrupted containment actions need recovery checking.")
            return 0
        for eid, state, detail in rows:
            print(f"{eid}: {state} — {detail}")
        return 0 if all(state in ("applied", "not_applied") for _, state, _ in rows) else 1

    ledger = defense.load(store)
    applied = {k: v for k, v in ledger.items() if v.get("status") == "applied"}
    proposed = {k: v for k, v in ledger.items() if v.get("status") == "proposed"}
    uncertain = {k: v for k, v in ledger.items() if v.get("status") in ("attempting", "uncertain", "not_applied")}

    if proposed:
        print(color("\nWAITING FOR YOU — proposed containment", "bold", t))
        for eid, e in sorted(proposed.items(), key=lambda kv: kv[1].get("at", 0), reverse=True):
            print(f"  {eid}  {e['title']}")
            print(f"        {e.get('preview', '')}")
            print(f"        approve: jarvis defend approve {eid}")
    if applied:
        print(color("\nJARVIS ACTED — reversible, undo any of these", "bold", t))
        for eid, e in sorted(applied.items(), key=lambda kv: kv[1].get("at", 0), reverse=True):
            print(f"  {eid}  {e['title']} — {e.get('detail', '')}  ({iso(e.get('at', 0))})")
            if e.get("expires_at"):
                print(f"        lifts automatically at {iso(e['expires_at'])}"
                      + (f" — last lift failed: {e['expire_error']}" if e.get("expire_error") else ""))
            print(f"        undo: jarvis defend undo {eid}")
    if uncertain:
        print(color("\nRECOVERY REVIEW REQUIRED — no repeat action was taken", "bold", t))
        for eid, e in sorted(uncertain.items(), key=lambda kv: kv[1].get("at", 0), reverse=True):
            print(f"  {eid}  {e['title']} — {e.get('detail', '')}")
        print("        inspect evidence, then run: jarvis defend reconcile")
    if not proposed and not applied and not uncertain:
        print("no automatic actions taken and nothing waiting.")
        print("see what is available with: jarvis defend actions")
    return 0


def cmd_answer(store, args):
    if not args.qid:
        open_q = questions.build(store, store.get_snapshots(), alert.load_conf())
        if not open_q:
            print("no open questions.")
            return 0
        print(color(f"{len(open_q)} question(s) for you"
                    + (f"; showing the top {min(15, len(open_q))}" if len(open_q) > 15 else "")
                    + ":\n", "bold", is_tty()))
        for q in open_q[:15]:
            print(f"  {q['id']}  [{(q['severity'] or '').upper()}] {q['prompt']}")
            print(f"        yes → {q['yes']}")
            print(f"        no  → {q['no']}")
            print(f"        {q['answer_cmd']}\n")
        return 0
    confirmed_by = None
    hit = acknowledge.resolve(store.get_snapshots(), args.qid)
    yes = (args.choice or "").strip().lower() in ("y", "yes", "mine", "me")
    if hit and yes and acknowledge.needs_confirmation(hit[0]):
        what = (f"CRITICAL: {hit[0].get('title', '')} ({hit[1]})\n"
                "Answering yes marks it as expected and stops alerts about it.")
        if not typed_confirmation(args.qid, what):
            print("not confirmed: a critical finding can only be confirmed by typing its id "
                  "at an interactive terminal")
            return 2
        confirmed_by = acknowledge.TERMINAL
    ok, message = questions.answer(store, args.qid, args.choice, confirmed_by=confirmed_by)
    print(message)
    return 0 if ok else 1


def add_parser(sub):
    p = sub.add_parser("defend", help="autonomous response: what JARVIS did and what awaits you")
    p.add_argument("action_arg", nargs="?", choices=["approve", "undo", "actions", "reconcile"],
                   help="approve or undo an action, or list available actions")
    p.add_argument("id", nargs="?", help="the action id (for approve/undo)")
    p.set_defaults(fn=lambda args, store: cmd_defend(store, args))

    a = sub.add_parser("answer", help="answer a proactive question (jarvis answer <id> yes|no)")
    a.add_argument("qid", nargs="?", help="the question id")
    a.add_argument("choice", nargs="?", default="", help="yes or no")
    a.set_defaults(fn=lambda args, store: cmd_answer(store, args))
    return p

