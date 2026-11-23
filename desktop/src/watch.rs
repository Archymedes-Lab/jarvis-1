//! What the tray shows and when to interrupt, decided from the daemon's pulse.
//!
//! Pure logic (no Tauri types) so every rule is unit-tested:
//!
//! * Unknown is never green. No pulse, a failed pulse, an unhealthy daemon or
//!   a blind collector can only make the tray more cautious, never calmer.
//! * Notify on change, not on state. The first pulse after start seeds what is
//!   already known (except criticals, which are always announced once); later
//!   pulses notify only for findings, blind collectors or a score crossing
//!   that were not there before. Owner-acknowledged findings never notify.
//! * Bounded. At most MAX_TOASTS per pulse; the rest are summarised.
//! * Plain words. Every pop-up says what happened in everyday language that
//!   anyone can follow (no "collector", "daemon" or "finding"), and keeps the
//!   facts the daemon reported: the finding's own title, the names of the checks
//!   that stopped, the score. A plain sentence never claims a compromise or a
//!   clean bill of health.

use serde_json::Value;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub const GATE: i64 = 90;
pub const OUTAGE_AFTER: Duration = Duration::from_secs(60);
pub const MAX_TOASTS: usize = 3;
/// A "stopped working" pop-up names at most this many checks, then "and N more".
pub const MAX_NAMED: usize = 3;
/// The daemon's reason for a check this edition cannot run without the elevated sensor.
const NEEDS_ADMIN_SENSOR: &str = "Needs administrator sensor";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Unknown,
    Good,
    Attention,
    Alarm,
}

/// What a notification is about, so the owner's preferences can mute a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Finding,
    Collector,
    Score,
    Outage,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Toast {
    pub kind: Kind,
    pub title: String,
    pub body: String,
}

#[derive(Debug)]
pub struct View {
    pub level: Level,
    pub line: String,
    pub toasts: Vec<Toast>,
}

#[derive(Default)]
pub struct Watch {
    seeded: bool,
    seen: HashSet<String>,
    blind: HashSet<String>,
    below_gate: bool,
    down_since: Option<Instant>,
    outage_announced: bool,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// The interface's plain guide, per finding category: [what it is, why it
/// matters, what to do]. One source for the app and the pop-ups.
static GUIDE: &str = include_str!("../ui/src/lib/guide.json");

fn guide(category: &str, part: usize) -> Option<String> {
    static TABLE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| serde_json::from_str(GUIDE).unwrap_or(Value::Null));
    t.get(category)?.get(part)?.as_str().map(str::to_string)
}

/// What a finding of this category is, in one everyday sentence, if known.
pub fn plain_means(category: &str) -> Option<String> {
    guide(category, 0)
}

/// What the person can do about a finding of this category, if known.
pub fn plain_next(category: &str) -> Option<String> {
    guide(category, 2)
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {many}") }
}

fn clip(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}

/// A pop-up for one new finding: what kind of thing it is, then exactly what
/// was seen. Only critical and high findings reach here (the pulse's URGENT).
fn finding_toast(u: &Value) -> Toast {
    let title = if s(u, "severity") == "critical" {
        "ARGUS-INSTINCT: please look at this now"
    } else {
        "ARGUS-INSTINCT: something is worth a look"
    };
    let seen = clip(&crate::brand::brand(s(u, "title")), 160);
    let cat = s(u, "category");
    let body = match (plain_means(cat), plain_next(cat)) {
        (Some(means), Some(next)) => format!("{means} {next} What it saw: {seen}"),
        (Some(means), None) => format!("{means} What it saw: {seen}"),
        (None, _) => format!("What it saw: {seen}. Open ARGUS-INSTINCT to see what this means and what to do."),
    };
    Toast { kind: Kind::Finding, title: title.into(), body }
}

impl Watch {
    pub fn pulse(&mut self, p: &Value) -> View {
        let mut toasts = Vec::new();
        if self.outage_announced {
            toasts.push(Toast {
                kind: Kind::Outage,
                title: "ARGUS-INSTINCT is watching again".into(),
                body: "The part that checks your computer is answering again.".into(),
            });
        }
        self.down_since = None;
        self.outage_announced = false;

        if p.get("ok").and_then(Value::as_bool) != Some(true) {
            return View {
                level: Level::Unknown,
                line: format!("ARGUS-INSTINCT could not finish its latest report (error: {})", s(p, "error")),
                toasts,
            };
        }

        let score = p.get("score").and_then(Value::as_i64);
        let open: Vec<&Value> = p
            .get("urgent")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|u| u.get("acknowledged") != Some(&Value::Bool(true))).collect())
            .unwrap_or_default();
        let critical = open.iter().any(|u| s(u, "severity") == "critical");
        let blind: Vec<&Value> = p.get("blind").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
        let healthy = p.get("healthy").and_then(Value::as_bool);

        let level = if critical {
            Level::Alarm
        } else if score.is_none() || healthy != Some(true) {
            Level::Unknown
        } else if !open.is_empty() || !blind.is_empty() || score.unwrap_or(0) < GATE {
            Level::Attention
        } else {
            Level::Good
        };

        let mut line = match score {
            Some(n) => format!("ARGUS-INSTINCT · safety score {n} ({})", s(p, "grade")),
            None => "ARGUS-INSTINCT · safety score not known yet".to_string(),
        };
        if !open.is_empty() {
            line += &format!(" · {} to look at", plural(open.len(), "thing", "things"));
        }
        if !blind.is_empty() {
            line += &format!(" · {} not working", plural(blind.len(), "check", "checks"));
        }
        if healthy == Some(false) {
            line += " · a problem with itself";
        }

        // New serious findings.
        let mut fresh: Vec<&Value> = Vec::new();
        for u in &open {
            let id = s(u, "id").to_string();
            if id.is_empty() || self.seen.contains(&id) {
                continue;
            }
            if self.seeded || s(u, "severity") == "critical" {
                fresh.push(u);
            }
            self.seen.insert(id);
        }
        for u in fresh.iter().take(MAX_TOASTS) {
            toasts.push(finding_toast(u));
        }
        if fresh.len() > MAX_TOASTS {
            toasts.push(Toast {
                kind: Kind::Finding,
                title: {
                    let more = fresh.len() - MAX_TOASTS;
                    format!("ARGUS-INSTINCT: {more} more {} to look at", if more == 1 { "thing" } else { "things" })
                },
                body: "Open ARGUS-INSTINCT to see them all, most urgent first.".into(),
            });
        }

        // Newly blind collectors.
        let now_blind: HashSet<String> = blind.iter().map(|b| s(b, "job").to_string()).collect();
        if self.seeded {
            // A check that needs the administrator sensor is not "stopped working":
            // it sees less because the sensor is absent (platform/admin_sensor.py).
            // An edition without the sensor reports these from the first pulse, which
            // is never announced. If they appear later, the sensor went away: that is
            // announced once, as what it is. Either way they count above.
            let newly: Vec<&Value> = blind.iter().copied().filter(|b| !self.blind.contains(s(b, "job"))).collect();
            let (sensor, mut gone): (Vec<&Value>, Vec<&Value>) =
                newly.into_iter().partition(|b| s(b, "reason") == NEEDS_ADMIN_SENSOR);
            if !sensor.is_empty() {
                toasts.push(Toast {
                    kind: Kind::Collector,
                    title: "ARGUS-INSTINCT lost its administrator sensor".into(),
                    body: format!(
                        "{} now {} less because the administrator sensor is not running. Open ARGUS-INSTINCT to see which, or reinstall the sensor.",
                        plural(sensor.len(), "check", "checks"),
                        if sensor.len() == 1 { "sees" } else { "see" },
                    ),
                });
            }
            gone.sort_by_key(|b| s(b, "job").to_string());
            if !gone.is_empty() {
                let mut names: Vec<String> = gone.iter().take(MAX_NAMED).map(|b| s(b, "label").to_string()).collect();
                if gone.len() > MAX_NAMED {
                    names.push(format!("and {} more", gone.len() - MAX_NAMED));
                }
                toasts.push(Toast {
                    kind: Kind::Collector,
                    title: "ARGUS-INSTINCT can't check everything right now".into(),
                    body: format!(
                        "{} stopped working: {}. Until {} again, ARGUS-INSTINCT can't tell whether {} of your computer {} okay. Nothing for you to do now; if this keeps happening, open ARGUS-INSTINCT to see why.",
                        if gone.len() == 1 { "This check" } else { "These checks" },
                        names.join(", "),
                        if gone.len() == 1 { "it works" } else { "they work" },
                        if gone.len() == 1 { "that part" } else { "those parts" },
                        if gone.len() == 1 { "is" } else { "are" },
                    ),
                });
            }
        }
        self.blind = now_blind;

        // The score crossing the release gate, either way, once per crossing.
        if let Some(n) = score {
            let below = n < GATE;
            if self.seeded && below && !self.below_gate {
                toasts.push(Toast {
                    kind: Kind::Score,
                    title: format!("Your safety score dropped to {n} out of 100"),
                    body: format!("That is below {GATE}, the level ARGUS-INSTINCT aims for. Open ARGUS-INSTINCT to see what changed."),
                });
            }
            self.below_gate = below;
        }

        self.seeded = true;
        View { level, line, toasts }
    }

    /// The daemon did not answer. Announce an outage once it has lasted
    /// OUTAGE_AFTER, because a silent tray would read as "all quiet".
    pub fn unreachable(&mut self, now: Instant) -> View {
        let since = *self.down_since.get_or_insert(now);
        let mut toasts = Vec::new();
        if !self.outage_announced && now.duration_since(since) >= OUTAGE_AFTER {
            self.outage_announced = true;
            toasts.push(Toast {
                kind: Kind::Outage,
                title: "ARGUS-INSTINCT has stopped watching your computer".into(),
                body: "The part that checks your computer has not answered for a minute, so nothing is being checked. ARGUS-INSTINCT keeps trying and will tell you when it is back.".into(),
            });
        }
        View { level: Level::Unknown, line: "ARGUS-INSTINCT is not answering · trying again".into(), toasts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pulse(score: i64, urgent: Value, blind: Value) -> Value {
        json!({"ok": true, "score": score, "grade": "secure", "healthy": true,
               "urgent": urgent, "blind": blind})
    }

    #[test]
    fn clean_is_good_and_quiet() {
        let v = Watch::default().pulse(&pulse(91, json!([]), json!([])));
        assert_eq!(v.level, Level::Good);
        assert!(v.toasts.is_empty());
        assert_eq!(v.line, "ARGUS-INSTINCT · safety score 91 (secure)");
    }

    #[test]
    fn unknown_is_never_green() {
        let mut w = Watch::default();
        assert_eq!(w.pulse(&json!({"ok": false, "error": "OSError"})).level, Level::Unknown);
        let mut p = pulse(95, json!([]), json!([]));
        p["healthy"] = Value::Null;
        assert_eq!(w.pulse(&p).level, Level::Unknown);
        p["healthy"] = json!(false);
        assert_eq!(w.pulse(&p).level, Level::Unknown);
        assert_eq!(w.unreachable(Instant::now()).level, Level::Unknown);
    }

    #[test]
    fn blind_collector_or_low_score_needs_attention() {
        let mut w = Watch::default();
        let blind = json!([{"job": "scan", "label": "Processes"}]);
        assert_eq!(w.pulse(&pulse(95, json!([]), blind)).level, Level::Attention);
        assert_eq!(w.pulse(&pulse(89, json!([]), json!([]))).level, Level::Attention);
    }

    #[test]
    fn first_pulse_seeds_highs_but_announces_criticals() {
        let mut w = Watch::default();
        let urgent = json!([
            {"id": "c1", "severity": "critical", "title": "ransom note"},
            {"id": "h1", "severity": "high", "title": "odd listener"}]);
        let v = w.pulse(&pulse(80, urgent.clone(), json!([])));
        assert_eq!(v.level, Level::Alarm);
        assert_eq!(v.toasts.len(), 1);
        assert!(v.toasts[0].body.contains("What it saw: ransom note"), "{}", v.toasts[0].body);
        assert_eq!(v.toasts[0].title, "ARGUS-INSTINCT: please look at this now");
        // Same findings again: nothing new to say.
        assert!(w.pulse(&pulse(80, urgent, json!([]))).toasts.is_empty());
    }

    #[test]
    fn new_finding_after_seed_notifies_once() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let urgent = json!([{"id": "h2", "severity": "high", "title": "new peer"}]);
        assert_eq!(w.pulse(&pulse(91, urgent.clone(), json!([]))).toasts.len(), 1);
        assert!(w.pulse(&pulse(91, urgent, json!([]))).toasts.is_empty());
    }

    #[test]
    fn acknowledged_findings_never_notify_or_alarm() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let urgent = json!([{"id": "c9", "severity": "critical", "title": "x", "acknowledged": true}]);
        let v = w.pulse(&pulse(91, urgent, json!([])));
        assert!(v.toasts.is_empty());
        assert_eq!(v.level, Level::Good);
    }

    #[test]
    fn toasts_are_bounded() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let many: Vec<Value> = (0..10)
            .map(|i| json!({"id": format!("h{i}"), "severity": "high", "title": "t"}))
            .collect();
        let v = w.pulse(&pulse(91, Value::Array(many), json!([])));
        assert_eq!(v.toasts.len(), MAX_TOASTS + 1);
        assert!(v.toasts.last().unwrap().title.contains("7 more things"), "{:?}", v.toasts.last());
    }

    #[test]
    fn newly_blind_collector_notifies() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let blind = json!([{"job": "sysmon", "label": "Sysmon"}]);
        let v = w.pulse(&pulse(91, json!([]), blind.clone()));
        assert_eq!(v.toasts.len(), 1);
        assert!(v.toasts[0].body.contains("Sysmon"));
        assert!(w.pulse(&pulse(91, json!([]), blind)).toasts.is_empty());
    }

    #[test]
    fn many_newly_blind_checks_are_named_briefly() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let blind: Vec<Value> = (0..7).map(|i| json!({"job": format!("j{i}"), "label": format!("Check {i}")})).collect();
        let v = w.pulse(&pulse(91, json!([]), Value::Array(blind)));
        assert_eq!(v.toasts.len(), 1);
        let body = &v.toasts[0].body;
        assert!(body.contains("Check 0, Check 1, Check 2, and 4 more"), "{body}");
        assert!(!body.contains("Check 6"));
        assert!(body.starts_with("These checks"));
    }

    #[test]
    fn an_edition_without_the_administrator_sensor_is_quiet_from_the_start() {
        let mut w = Watch::default();
        let blind = json!([{"job": "sysmon", "label": "Sysmon", "reason": "Needs administrator sensor"}]);
        let v = w.pulse(&pulse(91, json!([]), blind.clone()));
        assert!(v.toasts.is_empty(), "known from the first pulse: a limit of the edition");
        assert_eq!(v.level, Level::Attention, "but the tray stays cautious");
        assert!(w.pulse(&pulse(91, json!([]), blind)).toasts.is_empty());
    }

    #[test]
    fn losing_the_administrator_sensor_later_is_announced_once_as_what_it_is() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let blind = json!([
            {"job": "sysmon", "label": "Sysmon", "reason": "Needs administrator sensor"},
            {"job": "memscan", "label": "Memory", "reason": "Needs administrator sensor"},
            {"job": "net", "label": "Network", "freshness": "STALE"}]);
        let v = w.pulse(&pulse(91, json!([]), blind.clone()));
        assert_eq!(v.toasts.len(), 2);
        assert!(v.toasts[0].title.contains("lost its administrator sensor"));
        assert!(v.toasts[0].body.starts_with("2 checks now see less"), "{}", v.toasts[0].body);
        assert!(v.toasts[1].body.contains("Network") && !v.toasts[1].body.contains("Sysmon"));
        assert!(w.pulse(&pulse(91, json!([]), blind)).toasts.is_empty(), "once per change");
    }

    #[test]
    fn gate_crossing_notifies_once_per_crossing() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        assert_eq!(w.pulse(&pulse(89, json!([]), json!([]))).toasts.len(), 1);
        assert!(w.pulse(&pulse(88, json!([]), json!([]))).toasts.is_empty());
        assert!(w.pulse(&pulse(92, json!([]), json!([]))).toasts.is_empty());
        assert_eq!(w.pulse(&pulse(85, json!([]), json!([]))).toasts.len(), 1);
    }

    #[test]
    fn outage_announced_after_a_minute_then_recovery() {
        let mut w = Watch::default();
        w.pulse(&pulse(91, json!([]), json!([])));
        let t0 = Instant::now();
        assert!(w.unreachable(t0).toasts.is_empty());
        assert!(w.unreachable(t0 + Duration::from_secs(30)).toasts.is_empty());
        assert_eq!(w.unreachable(t0 + OUTAGE_AFTER).toasts.len(), 1);
        assert!(w.unreachable(t0 + OUTAGE_AFTER * 2).toasts.is_empty());
        let v = w.pulse(&pulse(91, json!([]), json!([])));
        assert_eq!(v.toasts[0].title, "ARGUS-INSTINCT is watching again");
    }

    /// Words a person who is not an engineer would not understand.
    const JARGON: [&str; 9] = ["daemon", "collector", "finding", "blind", "unobserved", "jarvis serve", "insight", "unhealthy", "`"];

    fn assert_plain(t: &Toast) {
        let all = format!("{} {}", t.title, t.body).to_lowercase();
        for w in JARGON {
            assert!(!all.contains(w), "jargon {w:?} in {all:?}");
        }
    }

    #[test]
    fn every_kind_of_popup_is_in_plain_words() {
        let mut w = Watch::default();
        w.pulse(&pulse(95, json!([]), json!([])));
        let urgent: Vec<Value> = (0..5)
            .map(|i| json!({"id": format!("f{i}"), "severity": if i == 0 {"critical"} else {"high"},
                            "title": "odd listener", "category": if i == 1 {"remote"} else {""}}))
            .collect();
        let blind = json!([{"job": "scan", "label": "Processes"}, {"job": "net", "label": "Network"}]);
        let mut all = w.pulse(&pulse(80, Value::Array(urgent), blind)).toasts;
        let t0 = Instant::now();
        w.unreachable(t0);
        all.extend(w.unreachable(t0 + OUTAGE_AFTER).toasts);
        all.extend(w.pulse(&pulse(80, json!([]), json!([]))).toasts);
        // findings (3 + "more"), checks, score, outage, back
        assert_eq!(all.len(), 8, "{all:?}");
        for t in &all {
            assert_plain(t);
        }
        let lines = [w.pulse(&pulse(80, json!([{"id": "z", "severity": "high", "title": "t"}]), json!([{"job": "a", "label": "A"}]))).line,
                     w.unreachable(Instant::now()).line];
        for l in lines {
            for j in JARGON {
                assert!(!l.to_lowercase().contains(j), "jargon {j:?} in tray line {l:?}");
            }
        }
    }

    #[test]
    fn plain_popups_keep_the_reported_facts() {
        let mut w = Watch::default();
        w.pulse(&pulse(95, json!([]), json!([])));
        let urgent = json!([{"id": "r", "severity": "high", "title": "RDP open to 0.0.0.0", "category": "remote"}]);
        let blind = json!([{"job": "scan", "label": "Processes"}]);
        let v = w.pulse(&pulse(70, urgent, blind));
        let f = v.toasts.iter().find(|t| t.kind == Kind::Finding).unwrap();
        // What it is, what to do, then exactly what was seen.
        let expect = format!("{} {} What it saw:", plain_means("remote").unwrap(), plain_next("remote").unwrap());
        assert!(f.body.starts_with(&expect), "{}", f.body);
        assert!(f.body.ends_with("What it saw: RDP open to 0.0.0.0"), "{}", f.body);
        let c = v.toasts.iter().find(|t| t.kind == Kind::Collector).unwrap();
        assert!(c.body.starts_with("This check stopped working: Processes."), "{}", c.body);
        let sc = v.toasts.iter().find(|t| t.kind == Kind::Score).unwrap();
        assert!(sc.title.contains("70 out of 100") && sc.body.contains("below 90"), "{sc:?}");
        assert!(v.line.contains("1 thing to look at") && v.line.contains("1 check not working"), "{}", v.line);
    }

    #[test]
    fn unknown_category_still_says_what_was_seen_and_long_titles_are_clipped() {
        let mut w = Watch::default();
        w.pulse(&pulse(95, json!([]), json!([])));
        let long = "x".repeat(400);
        let v = w.pulse(&pulse(95, json!([{"id": "l", "severity": "high", "title": long, "category": "no-such-kind"}]), json!([])));
        let b = &v.toasts[0].body;
        assert!(b.starts_with("What it saw: xxx") && b.contains("…") && b.chars().count() < 260, "{b}");
    }

    #[test]
    fn every_guide_category_has_a_plain_sentence() {
        let t: Value = serde_json::from_str(GUIDE).unwrap();
        let cats = t.as_object().unwrap();
        assert!(cats.len() > 10);
        for k in cats.keys() {
            assert!(plain_means(k).is_some_and(|m| m.ends_with('.')), "{k}");
            assert!(plain_next(k).is_some_and(|m| m.ends_with('.')), "{k}");
        }
    }
}
