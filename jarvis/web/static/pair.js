// Pairs this browser with the daemon.
//
// Two ways in, both ending in one POST to /api/session that answers with an
// HttpOnly cookie (nothing here stores a credential):
//  * a one-time link from the ARGUS-INSTINCT app: /pair?next=/x#code=<code>.
//    The code is in the fragment, which browsers never send to a server; this
//    script removes it from the address bar before doing anything else, so it
//    does not stay in history, then redeems it once (web/clients.py issue_link);
//  * a client token pasted by hand (`jarvis desktop pair`).
// A browser that is already paired is sent straight on, and no link is spent.
'use strict';

// Only a same-origin path may follow pairing: never another site, never "//host".
function safeNext(raw) {
  const value = String(raw || '');
  return /^\/(?![/\\])[A-Za-z0-9/_\-.]*$/.test(value) ? value : '/';
}

// The link code from a fragment like "#code=abc", or "" when there is none.
function codeFromHash(hash) {
  const params = new URLSearchParams(String(hash || '').replace(/^#/, ''));
  const code = params.get('code') || '';
  return /^[A-Za-z0-9_-]{32,64}$/.test(code) ? code : '';
}

const MESSAGES = {
  link_expired: ['That link was already used or has expired',
    'Pairing links work once and only for two minutes. Open the browser again from the ARGUS-INSTINCT app.'],
  too_many_clients: ['Too many paired browsers and apps',
    'Remove one you no longer use with jarvis desktop clients and jarvis desktop revoke ID, then try again.'],
};

async function postSession(body, fetchImpl) {
  const res = await fetchImpl('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  if (res.ok) return { ok: true };
  let message = 'ARGUS-INSTINCT refused this.';
  let reason = '';
  try {
    const parsed = await res.json();
    if (parsed && parsed.error) message = String(parsed.error);
    if (parsed && parsed.reason) reason = String(parsed.reason);
  } catch (e) { /* not JSON */ }
  return { ok: false, message, reason };
}

async function pair(token, fetchImpl) {
  return postSession({ token: String(token || '').trim() }, fetchImpl);
}

async function redeem(code, fetchImpl) {
  return postSession({ code }, fetchImpl);
}

// True when this browser's cookie already opens the API.
async function alreadyPaired(fetchImpl) {
  try {
    const res = await fetchImpl('/api/pulse', { cache: 'no-store', credentials: 'same-origin' });
    return res.ok;
  } catch (e) { return false; }
}

if (typeof document !== 'undefined' && document.getElementById('pair')) {
  const $ = (id) => document.getElementById(id);
  const out = $('result');
  const next = safeNext(new URLSearchParams(location.search).get('next'));
  const show = (id) => { for (const s of ['linking', 'done', 'manual']) $(s).hidden = s !== id; };
  const finish = () => {
    show('done');
    out.textContent = '';
    setTimeout(() => location.replace(next), 400);
  };
  const failLink = (title, text) => {
    show('manual');
    $('link-failed').hidden = false;
    $('manual-title').hidden = true;
    $('fail-title').textContent = title;
    $('fail-text').textContent = text;
    $('fail-text').hidden = false;
  };

  // Take the code out of the address bar first, whatever happens next.
  const code = codeFromHash(location.hash);
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);

  (async () => {
    if (code) show('linking');
    if (await alreadyPaired(fetch.bind(window))) return finish();
    if (!code) { $('token-details').open = location.search.includes('token=1'); return; }
    try {
      const result = await redeem(code, fetch.bind(window));
      if (result.ok) return finish();
      const [title, text] = MESSAGES[result.reason] || ['That link did not work', result.message];
      failLink(title, text);
    } catch (e) {
      failLink('ARGUS-INSTINCT did not answer', 'Check that it is running, then open the browser again from the app.');
    }
  })();

  $('pair').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const input = $('token');
    const button = $('submit');
    out.className = '';
    out.textContent = 'Pairing…';
    button.disabled = true;
    try {
      const result = await pair(input.value, fetch.bind(window));
      input.value = '';
      if (result.ok) return finish();
      out.className = 'bad';
      out.textContent = (MESSAGES[result.reason] || [null, result.message])[1];
    } catch (e) {
      out.className = 'bad';
      out.textContent = 'ARGUS-INSTINCT did not answer.';
    } finally {
      button.disabled = false;
    }
  });
}

if (typeof globalThis !== 'undefined') globalThis.__pair = { pair, redeem, safeNext, codeFromHash, alreadyPaired };
