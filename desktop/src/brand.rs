//! The product is ARGUS-INSTINCT: the display rule for notification text, the same
//! rule as the web pages, the interface (ui/src/lib/brand.ts) and the daemon
//! (jarvis/core/brand.py). tests/test_ui_brand.py keeps the keep-lists equal.

const NAME: &str = "JARVIS";
const BRAND: &str = "ARGUS-INSTINCT";
/// Real Windows objects keep their spelling so they can be found in Task Scheduler.
const KEEP: [&str; 5] = [
    " input hook",
    " independent health monitor",
    " connectivity guard",
    " native sensor",
    " Jarvis",
];

fn word(c: Option<char>) -> bool {
    c.map_or(false, |c| c.is_alphanumeric() || c == '_')
}

/// `text` with the old product name shown as ARGUS-INSTINCT. Idempotent.
pub fn brand(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut rest = text;
    let mut prev: Option<char> = None;
    while let Some(i) = rest.find(NAME) {
        let before = rest[..i].chars().last().or(prev);
        let after = &rest[i + NAME.len()..];
        let whole = !word(before) && !word(after.chars().next());
        let keep = after.starts_with("-1") || after.starts_with("-INSTINCT") || KEEP.iter().any(|k| after.starts_with(k));
        out.push_str(&rest[..i]);
        out.push_str(if whole && !keep { BRAND } else { NAME });
        prev = Some('S');
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::brand;

    #[test]
    fn same_cases_as_the_web_rule() {
        for (before, after) in [
            ("JARVIS is up", "ARGUS-INSTINCT is up"),
            ("JARVIS's view of JARVIS", "ARGUS-INSTINCT's view of ARGUS-INSTINCT"),
            ("JARVIS input hook", "JARVIS input hook"),
            ("JARVIS JarvisSensorDefender collector", "JARVIS JarvisSensorDefender collector"),
            ("restart jarvis.service", "restart jarvis.service"),
            ("JARVIS_NET_DIR", "JARVIS_NET_DIR"),
            ("ARGUS-INSTINCT ok", "ARGUS-INSTINCT ok"),
            ("", ""),
        ] {
            assert_eq!(brand(before), after, "{before}");
        }
    }
}
