//! The typed bridge between the bundled interface and the daemon.
//!
//! The interface is a page from `tauri://localhost`; it is cross-origin to
//! the daemon on purpose and has no network permission of its own. Every
//! request it needs goes through one of the commands below, which run here,
//! validate their arguments against the daemon's own formats, and make one
//! bounded loopback request. The page never sees the API token.
//!
//! Every request carries the app's paired client token (pairing.rs): the
//! daemon requires a credential on every route but liveness, and it no longer
//! hands its dashboard cookie to a peer whose account it cannot identify,
//! which from Windows across WSL it never can. Unpaired, every command fails
//! with the steps to pair.

use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::{pairing, pulse};

/// The state document is about 0.5 MB on a busy machine; 8 MB bounds a
/// misbehaving peer without truncating a real one.
pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_HEADER_LINE: u64 = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// A loaded machine has taken 9 s to build the state document.
const STATE_TIMEOUT: Duration = Duration::from_secs(45);
const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
/// The assistant may consult the local model.
const ASK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Parse a complete HTTP/1.x response: status, headers, body bounded by
/// Content-Length (or by EOF under `Connection: close`) and by MAX_BODY.
pub fn parse_response<R: BufRead>(r: &mut R) -> io::Result<Response> {
    let mut line = String::new();
    read_bounded_line(r, &mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| bad("bad status line"))?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        if read_bounded_line(r, &mut line)? == 0 {
            return Err(bad("headers ended early"));
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(bad("too many headers"));
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut resp = Response { status, headers, body: Vec::new() };
    if resp
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        return Err(bad("chunked bodies are not expected from the daemon"));
    }
    match resp.header("content-length").map(|v| v.parse::<usize>()) {
        Some(Ok(n)) if n > MAX_BODY => return Err(bad("body too large")),
        Some(Ok(n)) => {
            resp.body = vec![0; n];
            r.read_exact(&mut resp.body)?;
        }
        Some(Err(_)) => return Err(bad("bad content-length")),
        None => {
            r.by_ref().take(MAX_BODY as u64 + 1).read_to_end(&mut resp.body)?;
            if resp.body.len() > MAX_BODY {
                return Err(bad("body too large"));
            }
        }
    }
    Ok(resp)
}

fn read_bounded_line<R: BufRead>(r: &mut R, line: &mut String) -> io::Result<usize> {
    let n = r.by_ref().take(MAX_HEADER_LINE).read_line(line)?;
    if n as u64 == MAX_HEADER_LINE && !line.ends_with('\n') {
        return Err(bad("header line too long"));
    }
    Ok(n)
}

fn request(
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Response> {
    request_to(pulse::port(), method, path, token, body, timeout)
}

/// The same request to an explicit loopback port (tests aim it at a fake daemon).
fn request_to(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<Response> {
    let sock = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), pulse::CONNECT_TIMEOUT)?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(pulse::CONNECT_TIMEOUT))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: jarvis-desktop\r\n\
         Accept: application/json\r\nConnection: close\r\n"
    );
    if let Some(t) = token {
        head.push_str(&format!("X-JARVIS-Token: {t}\r\n"));
    }
    if let Some(b) = body {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", b.len()));
    }
    head.push_str("\r\n");
    // Headers and body in one write, so they arrive together: a server that
    // answers after one read and closes (an older daemon on a route that ignores
    // the body) then leaves nothing unread. Unread bytes make the OS reset the
    // connection, and Windows drops the unread reply with it (WSAECONNRESET 10054,
    // measured 2026-11-09 by running these tests on Windows).
    let mut out = head.into_bytes();
    if let Some(b) = body {
        out.extend_from_slice(b);
    }
    (&sock).write_all(&out)?;
    parse_response(&mut BufReader::new(sock))
}

fn unreachable(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => "ARGUS-INSTINCT is not running (nothing answers on the loopback port)".into(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "ARGUS-INSTINCT did not answer in time".into(),
        _ => format!("could not reach ARGUS-INSTINCT: {e}"),
    }
}

fn json_of(r: &Response) -> Result<Value, String> {
    serde_json::from_slice(&r.body).map_err(|_| format!("ARGUS-INSTINCT answered HTTP {} with a body that is not JSON", r.status))
}

/// A 403 that names the token: the pairing was revoked or never made.
fn refused_token(r: &Response, v: &Value) -> bool {
    r.status == 403 && v.get("error").and_then(Value::as_str).is_some_and(|m| m.contains("token"))
}

pub(crate) fn get_json(path: &str, timeout: Duration) -> Result<Value, String> {
    let t = pairing::client_token()?;
    let r = request("GET", path, Some(&t), None, timeout).map_err(|e| unreachable(&e))?;
    if r.status != 200 {
        let v = json_of(&r).unwrap_or(Value::Null);
        if refused_token(&r, &v) {
            return Err(REVOKED.into());
        }
        return Err(format!("ARGUS-INSTINCT answered HTTP {}", r.status));
    }
    json_of(&r)
}

const REVOKED: &str = "ARGUS-INSTINCT refused this app's pairing (revoked, or from another install). \
                       Pair again: `jarvis desktop pair --name desktop`, then replace client.token.";

/// A state-changing call with the paired client token.
fn post_json(path: &str, body: &Value, timeout: Duration) -> Result<Value, String> {
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let t = pairing::client_token()?;
    let r = request("POST", path, Some(&t), Some(&bytes), timeout).map_err(|e| unreachable(&e))?;
    let v = json_of(&r).unwrap_or(Value::Null);
    if refused_token(&r, &v) {
        return Err(REVOKED.into());
    }
    if (200..300).contains(&r.status) {
        return Ok(v);
    }
    let msg = v.get("message").or_else(|| v.get("error")).and_then(Value::as_str).unwrap_or("refused");
    Err(format!("ARGUS-INSTINCT refused: {msg} (HTTP {})", r.status))
}

// ---- argument formats, mirrored from the daemon ---------------------------

/// Scheduler job names: lower-case letters and underscores.
pub fn valid_job(job: &str) -> bool {
    (1..=32).contains(&job.len()) && job.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// Question ids (jarvis/response/questions.py): short and alphanumeric.
pub fn valid_question_id(id: &str) -> bool {
    (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fix proposal ids: `fx-` and eight hex digits, as the daemon checks.
pub fn valid_fix_id(id: &str) -> bool {
    id.len() == 11
        && id.starts_with("fx-")
        && id[3..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The app records intent only. Authorising a patch stays a deliberate step
/// outside it (the dashboard or `jarvis fix`), so it is not offered here.
pub fn valid_fix_decision(d: &str) -> bool {
    matches!(d, "approve" | "retry" | "reject")
}

pub(crate) async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| format!("worker failed: {e}"))?
}

// ---- commands ----------------------------------------------------------------

#[tauri::command]
pub async fn daemon_state() -> Result<Value, String> {
    blocking(|| get_json("/api/state", STATE_TIMEOUT)).await
}

/// What the app knows about the daemon and why: running, degraded (with the
/// collectors that cannot run), stopped, not installed, or not authorised.
#[tauri::command]
pub fn app_status() -> Value {
    serde_json::to_value(crate::lifecycle::current()).unwrap_or(Value::Null)
}

/// Cheap liveness for the sidebar: the pulse summary, or why it is missing.
#[tauri::command]
pub async fn daemon_status() -> Result<Value, String> {
    blocking(|| get_json("/api/pulse", ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn run_collector(job: String) -> Result<Value, String> {
    if !valid_job(&job) {
        return Err("unknown collector name".into());
    }
    blocking(move || post_json(&format!("/api/run?job={job}"), &json!({}), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn answer_question(id: String, choice: String) -> Result<Value, String> {
    if !valid_question_id(&id) || !matches!(choice.as_str(), "yes" | "no") {
        return Err("invalid answer".into());
    }
    blocking(move || post_json("/api/answer", &json!({ "id": id, "choice": choice }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn ask_jarvis(question: String, level: Option<String>, lang: Option<String>) -> Result<Value, String> {
    let lang = lang.filter(|l| valid_lang(l)).unwrap_or_else(|| "en".into());
    let level = if level.as_deref() == Some("simple") { "simple" } else { "expert" };
    let q: String = question.trim().chars().take(4000).collect();
    if q.is_empty() {
        return Err("ask a question first".into());
    }
    blocking(move || post_json("/api/ask", &json!({ "question": q, "level": level, "lang": lang }), ASK_TIMEOUT)).await
}

#[tauri::command]
pub async fn score_coach() -> Result<Value, String> {
    blocking(|| post_json("/api/score-coach", &json!({}), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn decide_fix(id: String, decision: String, reason: Option<String>) -> Result<Value, String> {
    if !valid_fix_id(&id) || !valid_fix_decision(&decision) {
        return Err("invalid fix decision".into());
    }
    let reason: String = reason.unwrap_or_default().chars().take(300).collect();
    blocking(move || {
        post_json(&format!("/api/fix/{decision}"), &json!({ "id": id, "reason": reason }), ACTION_TIMEOUT)
    })
    .await
}

#[cfg(windows)]
fn open_in_browser(url: &str) -> io::Result<()> {
    // FileProtocolHandler takes the URL as one argument; no shell parses it.
    std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn().map(|_| ())
}

#[cfg(not(windows))]
fn open_in_browser(url: &str) -> io::Result<()> {
    std::process::Command::new("xdg-open").arg(url).spawn().map(|_| ())
}

#[tauri::command]
pub async fn autopilot_status() -> Result<Value, String> {
    blocking(|| get_json("/api/autopilot", STATE_TIMEOUT)).await
}

/// Group keys are `job|category|folder`-style text from the daemon; the app
/// only bounds them. `authorize` (applying a change) is deliberately absent.
pub fn valid_case_key(k: &str) -> bool {
    (1..=600).contains(&k.chars().count()) && !k.chars().any(char::is_control)
}

pub fn valid_case_choice(c: &str) -> bool {
    matches!(c, "recognise" | "not_recognise" | "investigate_further")
}

#[tauri::command]
pub async fn autopilot_decide(key: String, choice: String) -> Result<Value, String> {
    if !valid_case_key(&key) || !valid_case_choice(&choice) {
        return Err("invalid decision".into());
    }
    blocking(move || post_json("/api/autopilot/decide", &json!({ "key": key, "choice": choice }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn autopilot_policy(auto_handle: bool) -> Result<Value, String> {
    blocking(move || post_json("/api/autopilot/policy", &json!({ "auto_handle": auto_handle }), ACTION_TIMEOUT)).await
}

/// Interface languages the assistant can be asked to answer in.
pub fn valid_lang(l: &str) -> bool {
    matches!(l, "en" | "fr" | "de" | "es" | "zh" | "ja" | "ko" | "pt" | "hi" | "ru" | "ar")
}

/// How long a pause may last. The daemon enforces the same list and always ends a pause by itself.
pub fn valid_pause_minutes(m: u32) -> bool {
    matches!(m, 15 | 60 | 240 | 1440)
}

#[tauri::command]
pub async fn pause_monitoring(minutes: u32) -> Result<Value, String> {
    if !valid_pause_minutes(minutes) {
        return Err("choose 15 minutes, 1 hour, 4 hours or 24 hours".into());
    }
    blocking(move || post_json("/api/pause", &json!({ "minutes": minutes }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn resume_monitoring() -> Result<Value, String> {
    blocking(|| post_json("/api/resume", &json!({}), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn protection_status() -> Result<Value, String> {
    blocking(|| get_json("/api/protection", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn protection_scan() -> Result<Value, String> {
    blocking(|| post_json("/api/protection/scan", &json!({}), ACTION_TIMEOUT)).await
}

// ---- phone alerts: pairing through the sealed relay ---------------------------
//
// The daemon holds the pairing state machine (jarvis/response/notify/pairing.py):
// a phone is paired only after the owner compares the 6-digit code here with the
// one on the phone and clicks. The app only forwards well-formed requests.

/// A confirm records the device and activates it on the relay, retried up to
/// five times: allow for that instead of reporting a timeout mid-way.
const PAIR_CONFIRM_TIMEOUT: Duration = Duration::from_secs(150);

/// Pairing session ids: 16 lowercase hex digits.
pub fn valid_pair_session(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The 6-digit comparison code.
pub fn valid_sas(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Device ids (or an unambiguous prefix of at least four characters).
pub fn valid_device_id(d: &str) -> bool {
    (4..=64).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[tauri::command]
pub async fn phone_status() -> Result<Value, String> {
    blocking(|| get_json("/api/phone/status", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_devices() -> Result<Value, String> {
    blocking(|| get_json("/api/phone/devices", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_pair_current() -> Result<Value, String> {
    blocking(|| get_json("/api/phone/pair", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_pair_start() -> Result<Value, String> {
    blocking(|| post_json("/api/phone/pair/start", &json!({}), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_pair_poll(session: String) -> Result<Value, String> {
    if !valid_pair_session(&session) {
        return Err("invalid pairing session".into());
    }
    blocking(move || post_json("/api/phone/pair/poll", &json!({ "session": session }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_pair_confirm(session: String, sas: String, same: bool) -> Result<Value, String> {
    if !valid_pair_session(&session) || !valid_sas(&sas) {
        return Err("invalid confirmation".into());
    }
    blocking(move || {
        post_json("/api/phone/pair/confirm", &json!({ "session": session, "sas": sas, "same": same }),
                  PAIR_CONFIRM_TIMEOUT)
    })
    .await
}

#[tauri::command]
pub async fn phone_pair_cancel(session: String) -> Result<Value, String> {
    if !valid_pair_session(&session) {
        return Err("invalid pairing session".into());
    }
    blocking(move || post_json("/api/phone/pair/cancel", &json!({ "session": session }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_revoke(device: String) -> Result<Value, String> {
    if !valid_device_id(&device) {
        return Err("invalid device id".into());
    }
    blocking(move || post_json("/api/phone/revoke", &json!({ "device": device }), ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn phone_test() -> Result<Value, String> {
    blocking(|| post_json("/api/phone/test", &json!({}), ACTION_TIMEOUT)).await
}

// ---- pages: location, coverage, world, processes ----------------------------

#[tauri::command]
pub async fn geo_state() -> Result<Value, String> {
    blocking(|| get_json("/api/geo", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn coverage_state() -> Result<Value, String> {
    blocking(|| get_json("/api/coverage", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn world_state() -> Result<Value, String> {
    blocking(|| get_json("/api/world", STATE_TIMEOUT)).await
}

#[tauri::command]
pub async fn procs_baseline() -> Result<Value, String> {
    blocking(|| get_json("/api/procs/baseline", STATE_TIMEOUT)).await
}

/// The daemon pages the app may open in the browser for the full view. A fixed
/// list: nothing the interface passes in is ever turned into an address.
pub fn page_path(page: &str) -> Option<&'static str> {
    match page {
        "dashboard" => Some("/ui/"),
        "coverage" => Some("/coverage"),
        "world" => Some("/world"),
        "procs" => Some("/procs"),
        "geo" => Some("/geo"),
        "classic" => Some("/classic"),
        _ => None,
    }
}

/// The daemon's one-time link code: URL-safe base64, as `secrets.token_urlsafe(32)` makes.
/// Checked before it is placed in an address.
pub fn valid_link_code(c: &str) -> bool {
    (32..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The address to open for `path`. With a link code the browser lands on /pair,
/// which pairs it once and goes on to `path`; the code rides in the fragment,
/// which a browser never sends to a server or puts in a Referer, and the page
/// removes it from the address bar. Without one (an older daemon, or minting
/// failed) the page itself opens and asks the browser to pair if it must.
pub fn browser_url(base: &str, path: &str, code: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    match code.filter(|c| valid_link_code(c)) {
        Some(c) => format!("{base}/pair?next={path}#code={c}"),
        None => format!("{base}{path}"),
    }
}

/// Ask the daemon for a one-time browser pairing code; None when it cannot
/// give one. Opening the page must still work, so a failure only costs the
/// shortcut, never the page.
fn mint_link_code() -> Option<String> {
    let v = post_json("/api/session/link", &json!({}), ACTION_TIMEOUT).ok()?;
    v.get("code").and_then(Value::as_str).filter(|c| valid_link_code(c)).map(str::to_string)
}

#[tauri::command]
pub async fn open_page(page: String) -> Result<Value, String> {
    let path = page_path(&page).ok_or("unknown page")?;
    let base = pulse::dashboard_url();
    blocking(move || {
        let code = mint_link_code();
        let url = browser_url(&base, path, code.as_deref());
        open_in_browser(&url).map_err(|e| format!("could not open the browser: {e}"))?;
        Ok(json!({ "ok": true, "paired_link": code.is_some() }))
    })
    .await
}

/// One consistent picture of the process table: the first full `snap` frame per
/// host plus the latest `status` frame, read from the live stream and then
/// dropped. Updates arrive as deltas on that stream; the page asks again every
/// few seconds instead, which keeps this a bounded read (time, bytes, frames).
pub fn collect_procs<R: BufRead>(r: &mut R, deadline: std::time::Instant) -> Value {
    let mut out = json!({ "snaps": {}, "status": Value::Null });
    let mut line = String::new();
    let mut total = 0usize;
    while std::time::Instant::now() < deadline && total < MAX_BODY {
        line.clear();
        match pulse::read_line(r, &mut line) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
        let Some(data) = line.trim_end().strip_prefix("data:") else { continue };
        let Ok(v) = serde_json::from_str::<Value>(data.trim()) else { continue };
        match v.get("k").and_then(Value::as_str) {
            Some("snap") => {
                if let (Some(h), Some(p)) = (v.get("h").and_then(Value::as_str), v.get("p")) {
                    if p.is_array() {
                        out["snaps"][h] = p.clone();
                    }
                }
            }
            Some("status") => out["status"] = v,
            _ => {}
        }
        if out["snaps"].get("win").is_some() && !out["status"].is_null() {
            break;
        }
    }
    out
}

#[tauri::command]
pub async fn procs_snapshot() -> Result<Value, String> {
    blocking(|| {
        let (status, mut reader) = pulse::open("/api/procs/stream").map_err(|e| unreachable(&e))?;
        if status != 200 {
            return Err(format!("ARGUS-INSTINCT answered HTTP {status}"));
        }
        Ok(collect_procs(&mut reader, std::time::Instant::now() + Duration::from_secs(8)))
    })
    .await
}

// ---- licence (premium content only; protection never consults it) ---------

/// Licence screen actions the daemon accepts (jarvis/web/licenceapi.py).
pub fn valid_licence_action(a: &str) -> bool {
    matches!(a, "activate" | "deactivate" | "refresh" | "upgrade" | "poll")
}

/// An optional promo code: 1 to 40 of A-Z a-z 0-9 - _ (jarvis/web/licenceapi.py PROMO). Codes and
/// discounts live in Stripe; the licence service looks the code up when checkout opens.
pub fn valid_promo(code: &str) -> bool {
    (1..=40).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The only pages this app opens in the browser: Archymedes checkout and the licence pages.
/// A purchase started in the app carries its claim id (`clm_` and 32 Crockford symbols); a
/// checkout may also carry a promo code (`&promo=` after the claim, or `?promo=` alone).
pub fn valid_licence_page(url: &str) -> bool {
    const BASE: &str = "https://pay.archymedes.xyz/";
    let Some(rest) = url.strip_prefix(BASE) else { return false };
    if matches!(rest, "manage" | "recover" | "buy/argus-server" | "buy/argus-desktop" | "buy/argus-desktop-monthly") {
        return true;
    }
    for offer in ["buy/argus-server?", "buy/argus-desktop?", "buy/argus-desktop-monthly?"] {
        let Some(query) = rest.strip_prefix(offer) else { continue };
        if let Some(code) = query.strip_prefix("promo=") {
            return valid_promo(code);
        }
        let Some(after) = query.strip_prefix("claim=clm_") else { return false };
        let (id, promo) = match after.split_once("&promo=") {
            Some((id, code)) => (id, Some(code)),
            None => (after, None),
        };
        return id.len() == 32
            && id.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
            && promo.is_none_or(valid_promo);
    }
    false
}

#[tauri::command]
pub async fn licence_state() -> Result<Value, String> {
    blocking(|| get_json("/api/licence", ACTION_TIMEOUT)).await
}

#[tauri::command]
pub async fn licence_action(action: String, key: Option<String>, plan: Option<String>, promo: Option<String>) -> Result<Value, String> {
    if !valid_licence_action(&action) {
        return Err("unknown licence action".into());
    }
    let key: String = key.unwrap_or_default().chars().take(200).collect();
    let plan = match plan.as_deref() { Some("server") => "server", Some("desktop-monthly") => "desktop-monthly", _ => "desktop" };
    // Passed on as typed (bounded); the daemon checks its shape and answers bad_promo.
    let promo: String = promo.unwrap_or_default().trim().chars().take(64).collect();
    blocking(move || post_json(&format!("/api/licence/{action}"), &json!({ "key": key, "plan": plan, "promo": promo }), ASK_TIMEOUT)).await
}

/// Open an allow-listed licence page in the default browser.
#[tauri::command]
pub async fn open_licence_page(url: String) -> Result<(), String> {
    if !valid_licence_page(&url) {
        return Err("that page is not an Archymedes licence page".into());
    }
    #[cfg(windows)]
    let mut cmd = std::process::Command::new("rundll32");
    #[cfg(windows)]
    cmd.args(["url.dll,FileProtocolHandler", &url]);
    #[cfg(not(windows))]
    let mut cmd = std::process::Command::new("xdg-open");
    #[cfg(not(windows))]
    cmd.arg(&url);
    cmd.spawn().map(|_| ()).map_err(|e| format!("could not open the browser: {e}; open {url} yourself"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn phone_arguments_are_bounded() {
        assert!(valid_pair_session("0123456789abcdef"));
        assert!(!valid_pair_session("0123456789ABCDEF"));
        assert!(!valid_pair_session("0123456789abcde"));
        assert!(valid_sas("012345"));
        assert!(!valid_sas("01234"));
        assert!(!valid_sas("01234a"));
        assert!(valid_device_id("abcd"));
        assert!(valid_device_id("Ab_c-9xyzAb_c-9xyzAb_c"));
        assert!(!valid_device_id("abc"));
        assert!(!valid_device_id("../etc"));
        assert!(!valid_device_id(&"a".repeat(65)));
    }

    #[test]
    fn licence_pages_and_actions_are_allow_listed() {
        assert!(valid_licence_page("https://pay.archymedes.xyz/manage"));
        assert!(valid_licence_page("https://pay.archymedes.xyz/buy/argus-desktop"));
        assert!(valid_licence_page("https://pay.archymedes.xyz/buy/argus-desktop-monthly"));
        assert!(valid_licence_page("https://pay.archymedes.xyz/buy/argus-desktop-monthly?claim=clm_0123456789ABCDEFGHJKMNPQRSTVWXYZ"));
        assert!(!valid_licence_page("https://pay.archymedes.xyz/buy/argus-desktop-monthly?claim=clm_short"));
        assert!(valid_licence_page("https://pay.archymedes.xyz/buy/argus-server?claim=clm_0123456789ABCDEFGHJKMNPQRSTVWXYZ"));
        for bad in ["https://evil.example/manage", "http://pay.archymedes.xyz/manage", "https://pay.archymedes.xyz/manage/../x",
                    "https://pay.archymedes.xyz/buy/argus-server?claim=clm_short", "https://pay.archymedes.xyz.evil/manage",
                    "https://pay.archymedes.xyz/buy/argus-server?claim=clm_0123456789ABCDEFGHJKMNPQRSTVWXYZ&x=1"] {
            assert!(!valid_licence_page(bad), "{bad}");
        }
        assert!(valid_licence_action("activate") && !valid_licence_action("../state"));
    }

    #[test]
    fn licence_pages_may_carry_a_promo_code_and_nothing_else() {
        const CLAIM: &str = "clm_0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        for ok in [format!("buy/argus-desktop?claim={CLAIM}&promo=LAUNCH_20-x"), "buy/argus-server?promo=FLEET10".into(),
                   format!("buy/argus-desktop-monthly?claim={CLAIM}&promo={}", "A".repeat(40))] {
            assert!(valid_licence_page(&format!("https://pay.archymedes.xyz/{ok}")), "{ok}");
        }
        for bad in [format!("buy/argus-desktop?claim={CLAIM}&promo="), format!("buy/argus-desktop?claim={CLAIM}&promo={}", "A".repeat(41)),
                    format!("buy/argus-desktop?claim={CLAIM}&promo=A&x=1"), format!("buy/argus-desktop?claim={CLAIM}&promo=A B"),
                    format!("buy/argus-desktop?claim={CLAIM}&promo=a%26b"), "buy/argus-desktop?promo=".into(),
                    "buy/argus-desktop?promo=A&claim=x".into(), "manage?promo=A".into(), "buy/argus-watch?promo=A".into(),
                    format!("buy/argus-desktop?promo=A&claim={CLAIM}")] {
            assert!(!valid_licence_page(&format!("https://pay.archymedes.xyz/{bad}")), "{bad}");
        }
        assert!(valid_promo("a") && valid_promo("Z-9_x") && !valid_promo("") && !valid_promo("é") && !valid_promo("a.b"));
    }

    fn parse(raw: &str) -> io::Result<Response> {
        parse_response(&mut Cursor::new(raw.as_bytes().to_vec()))
    }

    #[test]
    fn response_with_length_and_cookie() {
        let r = parse(
            "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: jarvis_token=\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; Path=/; SameSite=Strict\r\n\
             Content-Length: 5\r\n\r\nhello trailing",
        )
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert!(r.header("set-cookie").is_some());
    }

    #[test]
    fn body_to_eof_without_length() {
        let r = parse("HTTP/1.0 404 Not Found\r\n\r\n{\"error\": \"not found\"}").unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(json_of(&r).unwrap()["error"], "not found");
    }

    #[test]
    fn hostile_responses_are_errors() {
        assert!(parse("garbage\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").is_err());
        let long = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(20_000));
        assert!(parse(&long).is_err());
        let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: y\r\n".repeat(80));
        assert!(parse(&many).is_err());
        assert!(parse("HTTP/1.1 200 OK\r\nX: y\r\n").is_err(), "headers must end");
    }

    #[test]
    fn oversized_body_without_length_is_refused() {
        let raw = format!("HTTP/1.0 200 OK\r\n\r\n{}", "x".repeat(MAX_BODY + 10));
        assert!(parse(&raw).is_err());
    }

    // ---- against a fake daemon on a real socket --------------------------------

    use std::net::TcpListener;
    use std::thread;

    /// Serve one connection: capture the request, answer with `reply`, then
    /// optionally keep the socket open (to model a stalled peer).
    fn fake_daemon(reply: Vec<u8>, hold: Duration) -> (u16, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            let _ = sock.write_all(&reply);
            thread::sleep(hold);
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (port, h)
    }

    #[test]
    fn a_real_round_trip_sends_loopback_host_and_token_only_when_asked() {
        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\n{\"ok\": true}".to_vec(), Duration::ZERO);
        let r = request_to(port, "POST", "/api/answer", Some(&"ab".repeat(32)), Some(b"{}"), Duration::from_secs(5)).unwrap();
        assert_eq!(json_of(&r).unwrap()["ok"], true);
        let sent = h.join().unwrap();
        assert!(sent.starts_with("POST /api/answer HTTP/1.1\r\n"));
        assert!(sent.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
        assert!(sent.contains("X-JARVIS-Token: "));
        assert!(sent.contains("Content-Length: 2\r\n"));
        assert!(sent.ends_with("\r\n\r\n{}"), "the body arrives with the headers, in the server's first read");
        assert!(!sent.contains("Origin:"), "no Origin: the daemon treats the app as a local client");

        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(), Duration::ZERO);
        request_to(port, "GET", "/api/state", None, None, Duration::from_secs(5)).unwrap();
        assert!(!h.join().unwrap().contains("X-JARVIS-Token"), "no token unless the caller passes one");
    }

    #[test]
    fn a_stalled_daemon_times_out_instead_of_hanging() {
        // Headers promise 100 bytes, five arrive, then silence.
        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nhello".to_vec(), Duration::from_secs(3));
        let started = std::time::Instant::now();
        let r = request_to(port, "GET", "/api/state", None, None, Duration::from_millis(500));
        assert!(r.is_err());
        assert!(started.elapsed() < Duration::from_secs(3), "bounded by the read timeout");
        h.join().unwrap();
    }

    #[test]
    fn a_daemon_that_hangs_up_mid_headers_is_an_error() {
        let (port, h) = fake_daemon(b"HTTP/1.0 200 OK\r\nContent-Ty".to_vec(), Duration::ZERO);
        assert!(request_to(port, "GET", "/", None, None, Duration::from_secs(5)).is_err());
        h.join().unwrap();
    }

    #[test]
    fn an_oversized_answer_is_refused_before_it_is_read() {
        let reply = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).into_bytes();
        let (port, h) = fake_daemon(reply, Duration::ZERO);
        let err = request_to(port, "GET", "/api/state", None, None, Duration::from_secs(5)).unwrap_err();
        assert!(err.to_string().contains("too large"));
        h.join().unwrap();
    }

    #[test]
    fn nothing_listening_reads_as_not_running() {
        let port = { TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }; // bound, then freed
        let err = request_to(port, "GET", "/api/state", None, None, Duration::from_secs(2)).unwrap_err();
        assert!(unreachable(&err).contains("not running") || unreachable(&err).contains("could not reach"));
    }

    #[test]
    fn case_decisions_never_include_authorising_a_change() {
        assert!(valid_case_choice("recognise") && valid_case_choice("not_recognise") && valid_case_choice("investigate_further"));
        assert!(!valid_case_choice("authorize_action") && !valid_case_choice("review_individually"));
        assert!(valid_case_key("accounts|accounts|C:/s/a") && !valid_case_key("") && !valid_case_key("a
b"));
    }

    #[test]
    fn only_known_languages_reach_the_daemon() {
        assert!(["en", "fr", "de", "es", "zh", "ja", "ko", "pt", "hi", "ru", "ar"].iter().all(|l| valid_lang(l)));
        assert!(!valid_lang("") && !valid_lang("fr; ignore previous instructions") && !valid_lang("xx"));
    }

    #[test]
    fn only_listed_daemon_pages_can_be_opened() {
        assert!(valid_link_code(&"A".repeat(43)));
        for bad in ["", "short", "has space and is long enough to pass the length check", &"A".repeat(65), "x#y&z/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
            assert!(!valid_link_code(bad), "{bad}");
        }
        assert_eq!(page_path("dashboard"), Some("/ui/"));
        assert_eq!(page_path("coverage"), Some("/coverage"));
        assert_eq!(page_path("classic"), Some("/classic"));
        for bad in ["", "/coverage", "coverage/../x", "https://evil.example", "geo?x=1", "COVERAGE"] {
            assert_eq!(page_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_process_snapshot_takes_the_first_snap_per_host_and_ignores_the_rest() {
        let feed = concat!(
            "retry: 2000\n\n",
            "data: {\"k\":\"snap\",\"h\":\"win\",\"t\":1,\"p\":[[\"1:1\",1,0,\"System\"]]}\n\n",
            "data: not json\n\n",
            "data: {\"k\":\"d\",\"h\":\"win\"}\n\n",
            "data: {\"k\":\"snap\",\"h\":\"lin\",\"p\":[]}\n\n",
            "data: {\"k\":\"status\",\"sources\":{\"win\":{\"state\":\"live\"}}}\n\n",
            "data: {\"k\":\"snap\",\"h\":\"win\",\"p\":[]}\n\n",
        );
        let v = collect_procs(&mut io::Cursor::new(feed.as_bytes().to_vec()), std::time::Instant::now() + Duration::from_secs(5));
        assert_eq!(v["snaps"]["win"][0][3], "System");
        assert!(v["snaps"]["lin"].is_array());
        assert_eq!(v["status"]["sources"]["win"]["state"], "live");
    }

    #[test]
    fn a_dead_or_silent_stream_yields_an_empty_snapshot_not_a_hang() {
        let v = collect_procs(&mut io::Cursor::new(Vec::new()), std::time::Instant::now() + Duration::from_secs(5));
        assert!(v["snaps"].as_object().unwrap().is_empty() && v["status"].is_null());
        let expired = collect_procs(&mut io::Cursor::new(b"data: {\"k\":\"snap\",\"h\":\"win\",\"p\":[]}\n".to_vec()), std::time::Instant::now());
        assert!(expired["snaps"].as_object().unwrap().is_empty());
    }

    #[test]
    fn a_pause_is_one_of_the_fixed_lengths() {
        assert!([15, 60, 240, 1440].iter().all(|m| valid_pause_minutes(*m)));
        assert!(![0, 1, 14, 61, 1441, 100000].iter().any(|m| valid_pause_minutes(*m)), "no open-ended pause");
    }

    #[test]
    fn arguments_match_the_daemons_formats() {
        assert!(valid_job("scan") && valid_job("history_verify") && valid_job("sysmon_linux"));
        for bad in ["", "Scan", "scan;rm", "scan&job=x", "../x", "a b", &"x".repeat(33)] {
            assert!(!valid_job(bad), "{bad}");
        }
        assert!(valid_question_id("25ccafca"));
        assert!(!valid_question_id("") && !valid_question_id("a/b") && !valid_question_id(&"a".repeat(33)));
        assert!(valid_fix_id("fx-bc6b4886"));
        for bad in ["fx-BC6B4886", "fx-bc6b488", "fx-bc6b48861", "xx-bc6b4886", "fx-bc6b488g"] {
            assert!(!valid_fix_id(bad), "{bad}");
        }
        assert!(valid_fix_decision("approve") && valid_fix_decision("retry") && valid_fix_decision("reject"));
        assert!(!valid_fix_decision("authorize"), "authorising a patch is not offered by the app");
    }

    #[test]
    fn a_browser_link_carries_the_code_only_in_the_fragment() {
        let code = "A".repeat(43);
        let url = browser_url("http://127.0.0.1:8765/", "/coverage", Some(&code));
        assert_eq!(url, format!("http://127.0.0.1:8765/pair?next=/coverage#code={code}"));
        let (before, after) = url.split_once('#').unwrap();
        assert!(!before.contains(&code), "the part a browser sends to the server has no code");
        assert_eq!(after, format!("code={code}"));
    }

    #[test]
    fn without_a_valid_code_the_page_opens_directly() {
        assert_eq!(browser_url("http://127.0.0.1:8765", "/ui/", None), "http://127.0.0.1:8765/ui/");
        for bad in ["", "short", &"A".repeat(31), &"A".repeat(65), &format!("{}#", "A".repeat(42)), &format!("{}&", "A".repeat(42)), &"é".repeat(22)] {
            assert!(!valid_link_code(bad), "{bad}");
            assert_eq!(browser_url("http://127.0.0.1:8765", "/procs", Some(bad)), "http://127.0.0.1:8765/procs", "{bad}");
        }
    }

}
