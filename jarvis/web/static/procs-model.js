// The /procs lens rules, as pure functions (tested in Node by tests/test_procs_page.py).
//
// Two kinds of evidence decide how a process is drawn:
//
//   name   against the names the scan collector has recorded on this host
//          (/api/procs/baseline, web/procbaseline.py):
//            unknown   no baseline for this host yet, or it is unreadable
//            new       never recorded on this host
//            recent    first recorded within recent_s (a day)
//            known     recorded before
//            approved  recorded before and approved by you
//   ident  the daemon's verdict on the image behind it (web/procidentity.py),
//          three words [place, path, hash]; null until judged.
//
// They combine into one level: alarm (red), notice (amber), calm, or unknown.
// Only alarm and notice reach the change list; the rest would drown it.
//
// A start too short to sample (startVerdict) has no usable name history: the
// scan behind the name baseline looks once a minute, so it has never recorded
// most short-lived names (measured 2026-10-24: ~4 container health-check
// starts a second here, all "never seen"). Its place speaks for it, and the
// start history (every Sysmon start: the event log on Windows, start_images
// on Linux) says whether this exact program has started here before: path
// "same" if it started more than a day ago, "new" if never or only today,
// "unknown" while the history is younger than a day.

export const ROW = { key: 0, pid: 1, ppid: 2, name: 3, created: 4, cpu: 5, rss: 6, session: 7, ident: 8 };
export const LEVELS = ['unknown', 'calm', 'notice', 'alarm'];
export const rank = (level) => LEVELS.indexOf(level);

// The lens key for a name (same rule as procbaseline.norm): lower case, and a
// trailing process id such as WSL's "Relay(46877)" folded to "(#)".
export function norm(name) {
  return String(name || '').trim().toLowerCase().replace(/\(\d+\)$/, '(#)');
}

export function hostReady(baseline, h) {
  return !!(baseline && baseline.ok && baseline.hosts && baseline.hosts[h] && baseline.hosts[h].rows > 0);
}

export function classify(baseline, h, name, nowS) {
  if (!hostReady(baseline, h) || !name) return 'unknown';
  const row = baseline.hosts[h].names[norm(name)];
  if (!row) return 'new';
  const [first, , , approved] = row;
  if (approved) return 'approved';
  if (nowS - first < (baseline.recent_s || 86400)) return 'recent';
  return 'known';
}

// { level, reason } for one process. The strongest reason wins.
export function verdict(nameClass, ident) {
  const [place, path, hash] = Array.isArray(ident) ? ident : [null, null, null];
  if (place === 'fileless') return { level: 'alarm', reason: 'fileless' };
  if (path === 'moved') return { level: 'alarm', reason: 'moved' };
  if (nameClass === 'new') return { level: 'alarm', reason: 'new-name' };
  if (place === 'deleted') return { level: 'notice', reason: 'deleted' };
  if (nameClass === 'recent') return { level: 'notice', reason: 'recent-name' };
  if (hash === 'new' || hash === 'recent') return { level: 'notice', reason: 'new-binary' };
  if (nameClass === 'unknown' && !ident) return { level: 'unknown', reason: null };
  return { level: 'calm', reason: null };
}

// { level, reason } for a start that no table sampled (a Sysmon start only).
export function startVerdict(ident) {
  const [place, path, hash] = Array.isArray(ident) ? ident : [null, null, null];
  if (place === 'fileless') return { level: 'alarm', reason: 'fileless' };
  if (path === 'moved' && (place === 'temp' || place === 'user')) return { level: 'alarm', reason: 'moved' };
  if (path === 'new') return { level: 'notice', reason: 'first-run' };
  if (place === 'temp' && path !== 'same') return { level: 'notice', reason: 'temp' };
  if (hash === 'new') return { level: 'notice', reason: 'new-binary' };
  return { level: ident ? 'calm' : 'unknown', reason: null };
}

export const REASONS = {
  fileless: 'Runs from memory, with no file on disk',
  moved: 'Familiar name, unfamiliar place',
  'new-name': 'Never seen on this machine',
  deleted: 'Its file was replaced or removed since it started',
  'recent-name': 'First seen today',
  'new-binary': 'New binary today (a hash not seen before)',
  temp: 'Ran from a temporary folder',
  'first-run': 'First time this program has started here',
};

const PLACES = {
  system: 'Windows or system folder', program: 'Program Files', user: 'your user folders',
  temp: 'a temporary or download folder', kernel: 'the kernel (no file)', fileless: 'memory only',
  deleted: 'a file since replaced or removed', other: 'an unusual folder', unknown: 'unknown',
};
const PATHS = {
  same: 'same path as before', similar: 'a new version of a known install', moved: 'never from here before',
  new: 'no history yet', unknown: 'no path history to compare', pending: 'checking',
};
const HASHES = {
  known: 'seen before', recent: 'first seen today', new: 'never seen before', unknown: 'no hash recorded',
  pending: 'checking the history…',
};

// Text for the hover card: [[label, text], ...].
export function describeIdent(h, ident) {
  if (!Array.isArray(ident)) return [['Image', 'not checked yet']];
  const [place, path, hash] = ident;
  const out = [['Runs from', `${PLACES[place] || place}${place === 'unknown' ? '' : ' · ' + (PATHS[path] || path)}`]];
  if (h === 'win') out.push(['Binary', HASHES[hash] || hash]);
  return out;
}

// Watched names that were running during this view and are not now.
// `present` is a Set of lower-case names currently alive on host h;
// `everSeen` is a Set of watched names seen alive since the page opened.
export function missing(baseline, h, present, everSeen) {
  const watch = (baseline && baseline.watch && baseline.watch[h]) || [];
  return watch.filter((n) => everSeen.has(n) && !present.has(n));
}

// The change-list code for an event, or null when it is routine. `kind` is
// start, exit, short (a Sysmon start never sampled), missing or back.
export function changeLine(kind, level, watched) {
  if (kind === 'missing' || kind === 'back') return kind;
  if (kind === 'exit' && watched) return 'watched-exit';
  if (level !== 'alarm' && level !== 'notice') return null;
  return kind === 'exit' ? `${level}-exit` : kind === 'short' ? `${level}-short` : `${level}-start`;
}

export const CHANGE_TEXT = {
  'alarm-start': 'Started', 'notice-start': 'Started', 'alarm-exit': 'Exited', 'notice-exit': 'Exited',
  'alarm-short': 'Ran for under half a second', 'notice-short': 'Ran for under half a second',
  'watched-exit': 'Watched process exited', missing: 'Missing', back: 'Running again',
};
