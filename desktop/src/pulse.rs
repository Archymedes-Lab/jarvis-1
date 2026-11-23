//! Reads the daemon's live pulse (`GET /api/stream`, jarvis/web/stream.py).
//!
//! A deliberately small HTTP/1.x client over `std::net`: the only peer is the
//! loopback daemon, so there is no TLS, redirect, proxy or cookie handling to
//! get wrong, and no HTTP crate in the dependency tree. Every read is bounded
//! in time (READ_TIMEOUT, longer than the daemon's 15 s keepalive) and in size
//! (MAX_LINE), so a stalled or hostile peer surfaces as an error instead of a
//! hang or unbounded memory.

use serde_json::Value;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 8787;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const READ_TIMEOUT: Duration = Duration::from_secs(45);
pub const MAX_LINE: u64 = 256 * 1024;

/// The daemon's port: JARVIS_DESKTOP_PORT (a test daemon), else the `port`
/// file `jarvis native install` writes beside the app's client token (when
/// 8787 was taken on this machine), else 8787. The host is always 127.0.0.1;
/// only the port can be changed.
pub fn port() -> u16 {
    static PORT: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
    *PORT.get_or_init(|| {
        let env = |k: &str| std::env::var(k).ok();
        resolve_port(&env, &|p: &std::path::Path| std::fs::read_to_string(p).ok())
    })
}

fn parse_port(v: &str) -> Option<u16> {
    v.trim().parse().ok().filter(|p| *p != 0)
}

pub fn resolve_port(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&std::path::Path) -> Option<String>,
) -> u16 {
    if let Some(p) = env("JARVIS_DESKTOP_PORT").as_deref().and_then(parse_port) {
        return p;
    }
    crate::pairing::token_path(env)
        .and_then(|t| t.parent().map(|d| d.join("port")))
        .and_then(|f| read(&f))
        .as_deref()
        .and_then(parse_port)
        .unwrap_or(DEFAULT_PORT)
}

pub fn dashboard_url() -> String {
    format!("http://127.0.0.1:{}/", port())
}

/// Why a stream ended. `Refused` (403/503) means the daemon is up but will
/// not stream to us right now, so the caller should poll `/api/pulse`.
/// `Io` covers timeouts, resets and malformed or oversized input alike: the
/// caller's response (back off, show "unreachable") is the same for all.
#[derive(Debug)]
pub enum End {
    Closed,
    Refused,
    Io,
}

impl From<io::Error> for End {
    fn from(_: io::Error) -> Self {
        End::Io
    }
}

pub fn open(path: &str) -> io::Result<(u16, BufReader<TcpStream>)> {
    // Every data route needs the paired client token (pairing.rs). Unpaired,
    // the stream is not attempted: the caller's poll reports the steps.
    let token = crate::pairing::client_token()
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
    let (addr, port) = (SocketAddr::from(([127, 0, 0, 1], port())), port());
    let sock = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    sock.set_read_timeout(Some(READ_TIMEOUT))?;
    sock.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    (&sock).write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: jarvis-desktop\r\n\
             Accept: text/event-stream, application/json\r\nX-JARVIS-Token: {token}\r\n\
             Connection: close\r\n\r\n"
        )
        .as_bytes(),
    )?;
    let mut reader = BufReader::new(sock);
    let status = read_status(&mut reader)?;
    Ok((status, reader))
}

/// Parse the status line and skip the headers.
pub fn read_status<R: BufRead>(r: &mut R) -> io::Result<u16> {
    let mut line = String::new();
    read_line(r, &mut line)?;
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;
    loop {
        line.clear();
        if read_line(r, &mut line)? == 0 || line.trim_end().is_empty() {
            return Ok(code);
        }
    }
}

/// One line, at most MAX_LINE bytes; longer is an error, not a truncation.
pub fn read_line<R: BufRead>(r: &mut R, line: &mut String) -> io::Result<usize> {
    let n = r.by_ref().take(MAX_LINE).read_line(line)?;
    if n as u64 == MAX_LINE && !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    }
    Ok(n)
}

/// Feed every `pulse` event from an SSE body to `on`. Returns when the peer
/// closes (the daemon ends each stream after its lifetime).
pub fn read_events<R: BufRead>(r: &mut R, on: &mut dyn FnMut(Value)) -> Result<(), End> {
    let (mut event, mut data, mut line) = (String::new(), String::new(), String::new());
    loop {
        line.clear();
        if read_line(r, &mut line)? == 0 {
            return Err(End::Closed);
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            if event == "pulse" && !data.is_empty() {
                // A malformed event is skipped, never trusted in part.
                if let Ok(v) = serde_json::from_str::<Value>(&data) {
                    if v.is_object() {
                        on(v);
                    }
                }
            }
            event.clear();
            data.clear();
        } else if let Some(v) = l.strip_prefix("event:") {
            event = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(v.strip_prefix(' ').unwrap_or(v));
        }
        // "id:", "retry:" and ":" comments (keepalives) need no action.
    }
}

/// Hold one `/api/stream` connection open, delivering pulses until it ends.
pub fn stream(on: &mut dyn FnMut(Value)) -> End {
    match open("/api/stream") {
        Ok((200, mut r)) => match read_events(&mut r, on) {
            Ok(()) => End::Closed,
            Err(e) => e,
        },
        Ok(_) => End::Refused,
        Err(_) => End::Io,
    }
}

/// One `/api/pulse` snapshot, for when streaming is refused.
pub fn poll() -> io::Result<Value> {
    let (code, mut r) = open("/api/pulse")?;
    if code != 200 {
        return Err(io::Error::other(format!("HTTP {code}")));
    }
    let mut body = Vec::new();
    r.by_ref().take(MAX_LINE).read_to_end(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn port_env_then_file_then_default() {
        let none = |_: &str| None::<String>;
        let file = |_: &std::path::Path| Some("8791\n".to_string());
        let nofile = |_: &std::path::Path| None::<String>;
        let appdata = |k: &str| match k {
            "APPDATA" | "HOME" => Some("/x".to_string()),
            _ => None,
        };
        let both = |k: &str| match k {
            "JARVIS_DESKTOP_PORT" => Some("9000".to_string()),
            "APPDATA" | "HOME" => Some("/x".to_string()),
            _ => None,
        };
        assert_eq!(super::resolve_port(&both, &file), 9000);
        assert_eq!(super::resolve_port(&appdata, &file), 8791);
        assert_eq!(super::resolve_port(&appdata, &nofile), super::DEFAULT_PORT);
        assert_eq!(super::resolve_port(&none, &file), super::DEFAULT_PORT);
        let junk = |_: &std::path::Path| Some("0".to_string());
        assert_eq!(super::resolve_port(&appdata, &junk), super::DEFAULT_PORT);
    }

    use super::*;
    use std::io::Cursor;

    fn events(body: &str) -> (Vec<Value>, End) {
        let mut got = Vec::new();
        let end = read_events(&mut Cursor::new(body.as_bytes().to_vec()), &mut |v| got.push(v))
            .unwrap_err();
        (got, end)
    }

    #[test]
    fn status_and_headers() {
        let mut r = Cursor::new(b"HTTP/1.0 503 Busy\r\nX: y\r\n\r\nbody".to_vec());
        assert_eq!(read_status(&mut r).unwrap(), 503);
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "body");
    }

    #[test]
    fn garbage_status_is_an_error() {
        assert!(read_status(&mut Cursor::new(b"nonsense\r\n\r\n".to_vec())).is_err());
    }

    #[test]
    fn pulses_parsed_keepalives_and_other_events_ignored() {
        let body = "retry: 5000\n\n: keepalive\n\nid: a\nevent: pulse\ndata: {\"score\":91}\n\n\
                    event: other\ndata: {\"score\":1}\n\nevent: pulse\ndata: {\"score\":90}\n\n";
        let (got, end) = events(body);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0]["score"], 91);
        assert_eq!(got[1]["score"], 90);
        assert!(matches!(end, End::Closed));
    }

    #[test]
    fn malformed_or_non_object_pulse_is_skipped() {
        let (got, _) = events("event: pulse\ndata: {nope\n\nevent: pulse\ndata: 7\n\n");
        assert!(got.is_empty());
    }

    #[test]
    fn crlf_and_multiline_data() {
        let (got, _) = events("event: pulse\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n");
        assert_eq!(got[0]["a"], 1);
    }

    #[test]
    fn oversized_line_is_an_error_not_a_truncation() {
        let big = format!("data: {}\n", "x".repeat(MAX_LINE as usize + 10));
        let (_, end) = events(&big);
        assert!(matches!(end, End::Io));
    }
}
