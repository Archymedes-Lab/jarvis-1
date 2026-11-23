//! Bounded CLI bridge for metrics, governance, and a durable verified Rust
//! segment store. The established Python event log remains authoritative.

use jarvis_runtime::{
    live_metrics, open_store, peek_source_cursor, persist_verified, prune, should_defer,
    with_store, Ingest,
};
use std::io::{self, BufRead};
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("metrics") => {
            let m = live_metrics();
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "cpu_pct": m.cpu_pct,
                    "mem_available_pct": m.mem_available_pct,
                    "pressured": m.pressured,
                    "reason": m.reason,
                }))
                .unwrap_or_default()
            );
        }
        Some("defer") => {
            let job = args.get(2).cloned().unwrap_or_default();
            let pressured = args
                .get(3)
                .map(|s| s == "1" || s == "true")
                .unwrap_or(false);
            println!("{}", should_defer(&job, pressured));
        }
        Some("ingest") => {
            // JSON events on stdin are durably sealed beneath the supplied
            // root. The existing chain is fully verified before extension.
            // All-or-nothing: every line is validated before any segment is
            // persisted, so a rejected event leaves the store unchanged and
            // a mirror cursor derived from the store can never skip it.
            let root = match args.get(2) {
                Some(value) => Path::new(value),
                None => {
                    eprintln!("ingest requires a store root");
                    std::process::exit(2);
                }
            };
            let mut events = Vec::new();
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(error) => reject(&format!("cannot read input: {error}")),
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(ev) => events.push(ev),
                    Err(e) => reject(&e.to_string()),
                }
            }
            // One writer lock and one full verification cover the batch.
            let result = with_store(root, |state| {
                let mut ing = Ingest::new(
                    state.sealed_through,
                    &state.previous_hash,
                    state.next_segment,
                )
                .with_source_cursor(state.last_source_seq);
                let mut sealed = Vec::new();
                for ev in events {
                    match ing.push(ev) {
                        Ok(seq) => println!("{{\"ok\":true,\"seq\":{seq}}}"),
                        Err(e) => reject(&e),
                    }
                    if ing.due() {
                        sealed.extend(ing.seal()?);
                    }
                }
                sealed.extend(ing.seal()?);
                for (header, compressed) in &sealed {
                    persist_verified(root, state, header, compressed)?;
                }
                Ok(ing)
            });
            let ing = match result {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("failed to persist segment: {error}");
                    std::process::exit(1);
                }
            };
            println!(
                "{}",
                serde_json::json!({
                    "ok": true, "persisted": true, "last_seq": ing.next_seq,
                    "next_segment": ing.segment_no,
                })
            );
        }
        Some("verify") => {
            let root = match args.get(2) {
                Some(value) => Path::new(value),
                None => {
                    eprintln!("verify requires a store root");
                    std::process::exit(2);
                }
            };
            match open_store(root) {
                Ok(state) => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true, "segments": state.segments,
                        "last_seq": state.sealed_through,
                        "head": state.previous_hash,
                        "last_source_seq": state.last_source_seq,
                        "pruned_through": state.pruned_through,
                    })
                ),
                Err(error) => {
                    eprintln!("verification failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("cursor") => {
            let root = match args.get(2) {
                Some(value) => Path::new(value),
                None => {
                    eprintln!("cursor requires a store root");
                    std::process::exit(2);
                }
            };
            match peek_source_cursor(root) {
                Ok(cursor) => println!(
                    "{}",
                    serde_json::json!({"ok": true, "last_source_seq": cursor})
                ),
                Err(error) => {
                    eprintln!("cursor failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some("prune") => {
            let root = args.get(2).map(Path::new);
            let budget = args.get(3).and_then(|value| value.parse::<u64>().ok());
            let (root, budget) = match (root, budget) {
                (Some(root), Some(budget)) => (root, budget),
                _ => {
                    eprintln!("prune requires a store root and a byte budget");
                    std::process::exit(2);
                }
            };
            match prune(root, budget) {
                Ok((removed, retained)) => println!(
                    "{}",
                    serde_json::json!({
                        "ok": true, "removed_segments": removed,
                        "retained_bytes": retained,
                    })
                ),
                Err(error) => {
                    eprintln!("prune failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: jarvis-runtime (metrics|defer <job> <pressured>|ingest <root>|verify <root>|cursor <root>|prune <root> <bytes>)");
            std::process::exit(2);
        }
    }
}

/// Report a rejected input and exit before anything is persisted.
fn reject(error: &str) -> ! {
    println!("{{\"ok\":false,\"error\":{}}}", serde_json::json!(error));
    std::process::exit(1);
}
