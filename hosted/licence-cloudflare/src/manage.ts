// People-facing pages on pay.archymedes.xyz: the thank-you page, /manage (magic link), /recover and /link.
// docs/LICENSING-ARCHITECTURE.md §5b, §5e.
//
// - No plaintext email in D1: an address is hashed (HMAC with KEY_PEPPER) to find purchases, and the
//   address itself travels only inside sealed (AES-GCM) values: the emailed link and the session cookie.
// - /recover and /manage answer the same whether or not the email bought anything, and are throttled
//   per email (3 per hour) and per IP.
// - Magic links: single use, 15 minutes, stored as a hash; opening one needs a click (POST), so mail
//   scanners that fetch links do not use them up. Sessions: 30 minutes, HttpOnly, Secure, SameSite=Strict,
//   and every POST carries the session's CSRF token and our Origin.
import { emailHash, randomId, sha256Hex } from "./keys";
import { type Activation, audit, constantTimeEqual, type Deps, EMAIL_PER_HOUR, type Env, type Licence, limited,
         MAGIC_TTL, OFFERS, payOrigin, pepper, REVEAL_WINDOW, sec, SESSION_TTL, standing, support } from "./env";
import { bindClaim, covers, issue, keyEmail, keyOf, normCode, portalUrl, release, releaseLimitText, releasesLeft, type Claim } from "./licence";
import { esc, formOf, page, redirect, sameOrigin, seal, sendMail, simplePage, unseal } from "./web";
import { stripe, StripeError } from "./stripe";

const EMAIL = /^[^\s@<>"]{1,64}@[^\s@<>"]{1,190}\.[^\s@<>"]{2,}$/;
const SESSION_ID = /^cs_(test|live)_[A-Za-z0-9]+$/;
const day = (s: number | null) => (s == null ? "no end date" : new Date(s * 1000).toISOString().slice(0, 10));
const paid = (s: any) => s?.status === "complete" && (s?.payment_status === "paid" || s?.payment_status === "no_payment_required");

// ---------------------------------------------------------------------------------------------
// Thank-you page: GET /thanks?session_id=cs_…
// ---------------------------------------------------------------------------------------------
export async function thanks(env: Env, deps: Deps, url: URL): Promise<Response> {
  const id = url.searchParams.get("session_id") || "";
  const pay = payOrigin(env);
  if (!SESSION_ID.test(id)) return simplePage(400, "No purchase here", "This page needs the link Stripe sent you back with.", `${pay}/recover`, "Lost your key?");
  let session: any;
  try {
    session = await stripe(deps.fetch, env.STRIPE_SECRET_KEY, "GET", `/checkout/sessions/${id}`, new URLSearchParams({ "expand[0]": "subscription" }));
  } catch (err) {
    if (err instanceof StripeError && err.status === 404) return simplePage(404, "No purchase here", "Stripe does not know this purchase.");
    return simplePage(502, "One moment", "The payment service is not answering. Reload this page in a minute; your key is also on its way by email.");
  }
  if (session?.metadata?.app !== "argus" || !OFFERS[session.metadata.offer]) return simplePage(404, "No purchase here", "This is not an Argus purchase.");
  if (!paid(session)) {
    if (session.status === "expired") return simplePage(200, "Payment not completed", "Nothing was charged.", `${pay}/buy/${session.metadata.offer}`, "Try again");
    return page("Payment processing", `<h1>Your payment is processing</h1><p>This page refreshes by itself. Your key appears here and in your email as soon as the payment is confirmed.</p>`, { refresh: 5 });
  }
  const { lic } = await issue(env, deps, session);
  const claimId = typeof session.metadata?.claim === "string" ? session.metadata.claim : "";
  let claimedLabel = "";
  if (claimId) {
    const claim = await env.DB.prepare("SELECT * FROM claims WHERE id_hash = ?").bind(await sha256Hex(claimId)).first<Claim>();
    if (claim) {
      const r = claim.licence_id ? null : await bindClaim(env, deps, claim, lic, "stripe");
      if (claim.licence_id === lic.id || (r && typeof r === "object" && r.ok)) claimedLabel = claim.label;
    }
  }
  const offer = OFFERS[lic.offer];
  const created = typeof session.created === "number" ? session.created : lic.created_at;
  const email = typeof session.customer_details?.email === "string" ? session.customer_details.email : "";
  const masked = email ? `${email[0]}***${email.slice(email.lastIndexOf("@"))}` : "your email";
  if (sec(deps) - created > REVEAL_WINDOW) {
    return page("Thank you", `<h1>Thank you for buying ${esc(offer.product)}</h1><p>Your key was emailed to ${esc(masked)}. ` +
      `For your security it is shown here only on the day of purchase.</p><p><a href="${pay}/recover">Email me my key again</a> · <a href="${pay}/manage">Manage your licence</a></p>`);
  }
  const key = await keyOf(env, lic);
  const done = claimedLabel
    ? `<div class="card ok"><b>Argus on “${esc(claimedLabel)}” is already activated.</b> Go back to Argus; it picks the licence up within a few seconds.</div>`
    : "";
  const how = offer.plan === "server"
    ? `<p>${lic.seats > 1 ? `On each server (up to ${lic.seats}), run the same command:` : "On the server, run:"}</p><div class="key" id="cmd">argus licence activate ${esc(key)}</div>`
    : `<p>In Argus, open <b>Licence</b>, paste the key and choose <b>Activate</b>, or use the button below on that computer.</p>`;
  const body = `<h1>Thank you for buying ${esc(offer.product)}</h1>${done}
<p>Your licence key:</p><div class="key" id="key">${esc(key)}</div>
<div class="row"><button class="primary" id="copy" type="button">Copy key</button>
<a class="btn" href="argus://activate?key=${encodeURIComponent(key)}">Open in Argus</a><span id="copied" class="muted" aria-live="polite"></span></div>
${claimedLabel ? "<h2>Another computer instead?</h2><p>Keep the key: release this one at Manage your licence, then activate the key there.</p>" : `<h2>Activate it</h2>${how}`}
<p class="muted">The key covers ${covers(offer.plan, lic.seats)}. We also emailed it to ${esc(masked)}. ` +
    `It is shown here only today; keep the email.</p>
<h2>Later</h2><p><a href="${pay}/manage">Manage your licence</a> (see where it is active, move it, billing) · <a href="${pay}/recover">Lost your key?</a></p>`;
  const script = `document.getElementById("copy").addEventListener("click",function(){var k=document.getElementById("key").textContent;` +
    `(navigator.clipboard?navigator.clipboard.writeText(k):Promise.reject()).then(function(){document.getElementById("copied").textContent="Copied.";},` +
    `function(){var r=document.createRange();r.selectNodeContents(document.getElementById("key"));var s=getSelection();s.removeAllRanges();s.addRange(r);` +
    `document.getElementById("copied").textContent="Selected: press Ctrl+C (or Cmd+C).";});});`;
  return page(`Your ${offer.product} key`, body, { script });
}

// ---------------------------------------------------------------------------------------------
// Email throttle and the uniform answer
// ---------------------------------------------------------------------------------------------
async function throttled(env: Env, deps: Deps, bucket: string): Promise<boolean> {
  const now = sec(deps);
  await env.DB.prepare("DELETE FROM throttle WHERE at < ?").bind(now - 86400).run();
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM throttle WHERE bucket = ? AND at > ?").bind(bucket, now - 3600).first<{ n: number }>();
  if ((r?.n ?? 0) >= EMAIL_PER_HOUR) return true;
  await env.DB.prepare("INSERT INTO throttle (bucket, at) VALUES (?, ?)").bind(bucket, now).run();
  return false;
}

const sent = (what: string) => page("Check your email",
  `<h1>Check your email</h1><p>If that address bought Argus, ${esc(what)} is on its way to it. It can take a minute; look in spam too.</p>` +
  `<p class="muted">Nothing arriving? Make sure it is the address you paid with at checkout.</p>`);

async function licencesFor(env: Env, eh: string): Promise<Licence[]> {
  return (await env.DB.prepare("SELECT * FROM licences_v2 WHERE email_hash = ? ORDER BY created_at").bind(eh).all<Licence>()).results ?? [];
}

const emailForm = (action: string, button: string, extra = "") =>
  `<form method="post" action="${action}"><div class="row"><input type="email" name="email" required autocomplete="email" placeholder="you@example.com" aria-label="Purchase email">` +
  `${extra}<button class="primary" type="submit">${esc(button)}</button></div></form>`;

// ---------------------------------------------------------------------------------------------
// /recover
// ---------------------------------------------------------------------------------------------
export async function recover(req: Request, env: Env, deps: Deps): Promise<Response> {
  if (req.method === "GET")
    return page("Lost your key?", `<h1>Lost your key?</h1><p>Enter the email you paid with and we will email your Argus licence key again.</p>` +
      emailForm("/recover", "Email my key") + `<p class="muted"><a href="/manage">Manage your licence</a> instead</p>`);
  if (!sameOrigin(req, env)) return simplePage(403, "Not allowed", "This form only works from this site.");
  if (await limited(env.RL_EMAIL, req, "recover:")) return simplePage(429, "Please wait a moment", "Too many requests from this network. Try again in a minute.");
  const email = ((await formOf(req))?.get("email") || "").trim();
  if (!EMAIL.test(email)) return simplePage(400, "That is not an email address", "Go back and check it.", "/recover", "Try again");
  const eh = await emailHash(pepper(env), email);
  if (!(await throttled(env, deps, `recover:${eh}`))) {
    const lics = (await licencesFor(env, eh)).filter((l) => l.status === "active");
    if (lics.length) {
      const blocks = await Promise.all(lics.map(async (l) => keyEmail(env, l, await keyOf(env, l)).text));
      await sendMail(env, deps, email, lics.length === 1 ? keyEmail(env, lics[0], "").subject : "Your Argus licence keys",
                     blocks.join("\n\n----\n\n"));
      for (const l of lics) await audit(env, deps, l.id, "key resent (recover)", "owner");
    }
  }
  return sent("your key");
}

// ---------------------------------------------------------------------------------------------
// /manage: email → magic link → session
// ---------------------------------------------------------------------------------------------
const cookieName = (env: Env) => (payOrigin(env).startsWith("https://") ? "__Host-argus_manage" : "argus_manage");
const cookieAttrs = (env: Env) => `Path=/; HttpOnly; SameSite=Strict${payOrigin(env).startsWith("https://") ? "; Secure" : ""}`;

type Session = { email: string; email_hash: string; csrf: string; idHash: string };

async function session(req: Request, env: Env, deps: Deps): Promise<Session | null> {
  const name = cookieName(env);
  const raw = (req.headers.get("Cookie") || "").split(/;\s*/).find((c) => c.startsWith(`${name}=`))?.slice(name.length + 1) || "";
  const [sid, sealed] = raw.split(".");
  if (!sid || !sealed || sid.length > 64) return null;
  const idHash = await sha256Hex(sid);
  const row = await env.DB.prepare("SELECT * FROM manage_sessions WHERE id_hash = ?").bind(idHash).first<{ email_hash: string; csrf: string; expires_at: number }>();
  if (!row || sec(deps) > row.expires_at) return null;
  const v = await unseal(pepper(env), sealed);
  if (!v || typeof v.e !== "string" || !constantTimeEqual(await emailHash(pepper(env), v.e), row.email_hash)) return null;
  return { email: v.e, email_hash: row.email_hash, csrf: row.csrf, idHash };
}

export async function manage(req: Request, env: Env, deps: Deps, path: string, url: URL): Promise<Response> {
  const pay = payOrigin(env);
  const next = url.searchParams.get("next") === "link" ? "link" : "";
  if (path === "/manage" && req.method === "GET") {
    if (await session(req, env, deps)) return redirect(next === "link" ? "/link" : "/manage/home");
    return page("Manage your licence", `<h1>Manage your Argus licence</h1><p>Enter the email you paid with. We will email you a sign-in link ` +
      `(valid 15 minutes) to see where your licence is active, move it, get your key again, or manage billing.</p>` +
      emailForm("/manage/link", "Email me a link", next ? `<input type="hidden" name="next" value="link">` : "") +
      `<p class="muted"><a href="/recover">Just need your key?</a></p>`);
  }
  if (path === "/manage/open" && req.method === "GET") {
    const t = url.searchParams.get("t") || "";
    return page("Sign in", `<h1>Sign in to manage your licence</h1><form method="post" action="/manage/open"><input type="hidden" name="t" value="${esc(t)}">` +
      `<button class="primary" type="submit">Continue</button></form><p class="muted">The link works once, for 15 minutes.</p>`);
  }
  if (req.method !== "POST") return simplePage(404, "Not found", "There is nothing here.", `${pay}/manage`, "Manage your licence");
  if (!sameOrigin(req, env)) return simplePage(403, "Not allowed", "This form only works from this site.");
  const form = await formOf(req);
  if (!form) return simplePage(400, "Bad request", "That request was too large.");
  const now = sec(deps);
  const P = pepper(env);

  if (path === "/manage/link") {
    if (await limited(env.RL_EMAIL, req, "manage:")) return simplePage(429, "Please wait a moment", "Too many requests from this network. Try again in a minute.");
    const email = (form.get("email") || "").trim();
    if (!EMAIL.test(email)) return simplePage(400, "That is not an email address", "Go back and check it.", "/manage", "Try again");
    const eh = await emailHash(P, email);
    if (!(await throttled(env, deps, `manage:${eh}`)) && (await licencesFor(env, eh)).length) {
      const token = await seal(P, { e: email, n: randomId("", 16), x: now + MAGIC_TTL, next: form.get("next") === "link" ? "link" : "" });
      await env.DB.prepare("DELETE FROM magic_links WHERE expires_at < ?").bind(now - 86400).run();
      await env.DB.prepare("INSERT INTO magic_links (token_hash, email_hash, expires_at) VALUES (?, ?, ?)").bind(await sha256Hex(token), eh, now + MAGIC_TTL).run();
      await sendMail(env, deps, email, "Your Argus licence sign-in link",
        [`Open this link to manage your Argus licence (it works once, for 15 minutes):`, "", `${pay}/manage/open?t=${token}`, "",
         "If you did not ask for it, ignore this email; nothing changes.", "", "Archymedes"].join("\n"));
    }
    return sent("a sign-in link");
  }

  if (path === "/manage/open") {
    const t = form.get("t") || "";
    const v = await unseal(P, t);
    const th = await sha256Hex(t);
    const row = v ? await env.DB.prepare("SELECT * FROM magic_links WHERE token_hash = ?").bind(th).first<{ email_hash: string; expires_at: number; used_at: number | null }>() : null;
    const used = row && !row.used_at && now <= row.expires_at
      ? (await env.DB.prepare("UPDATE magic_links SET used_at = ? WHERE token_hash = ? AND used_at IS NULL").bind(now, th).run()).meta?.changes
      : 0;
    if (!v || !row || !used || typeof v.e !== "string") return simplePage(410, "This link has expired", "Sign-in links work once, for 15 minutes. Ask for a new one.", "/manage", "Email me a new link");
    const sid = randomId("", 32), csrf = randomId("", 24);
    await env.DB.prepare("DELETE FROM manage_sessions WHERE expires_at < ?").bind(now).run();
    await env.DB.prepare("INSERT INTO manage_sessions (id_hash, email_hash, csrf, expires_at) VALUES (?, ?, ?, ?)")
      .bind(await sha256Hex(sid), row.email_hash, csrf, now + SESSION_TTL).run();
    const cookie = `${cookieName(env)}=${sid}.${await seal(P, { e: v.e })}; Max-Age=${SESSION_TTL}; ${cookieAttrs(env)}`;
    return redirect(v.next === "link" ? "/link" : "/manage/home", { "Set-Cookie": cookie });
  }

  const s = await session(req, env, deps);
  if (!s) return redirect("/manage");
  if (!constantTimeEqual(form.get("csrf") || "", s.csrf)) return simplePage(403, "Not allowed", "This page is out of date. Go back and reload it.");
  const lic = form.get("licence_id")
    ? await env.DB.prepare("SELECT * FROM licences_v2 WHERE id = ? AND email_hash = ?").bind(form.get("licence_id"), s.email_hash).first<Licence>()
    : null;

  if (path === "/manage/signout") {
    await env.DB.prepare("DELETE FROM manage_sessions WHERE id_hash = ?").bind(s.idHash).run();
    return redirect("/manage", { "Set-Cookie": `${cookieName(env)}=; Max-Age=0; ${cookieAttrs(env)}` });
  }
  if (path === "/manage/release") {
    const act = await env.DB.prepare(`SELECT a.* FROM activations_v2 a JOIN licences_v2 l ON l.id = a.licence_id
                                      WHERE a.id = ? AND l.email_hash = ?`).bind(form.get("activation_id") || "", s.email_hash).first<Activation>();
    if (!act) return redirect("/manage/home?m=missing");
    const r = await release(env, deps, act, "owner");
    return redirect(`/manage/home?m=${r === "limit" ? "limit" : "released"}`);
  }
  if (path === "/manage/resend") {
    if (!lic) return redirect("/manage/home?m=missing");
    const m = keyEmail(env, lic, await keyOf(env, lic));
    const ok = await sendMail(env, deps, s.email, m.subject, m.text);
    await audit(env, deps, lic.id, "key resent (manage)", "owner");
    return redirect(`/manage/home?m=${ok ? "sent" : "mailfail"}`);
  }
  if (path === "/manage/portal") {
    const to = lic ? await portalUrl(env, deps, lic) : null;
    return to ? redirect(to) : redirect("/manage/home?m=portal");
  }
  return simplePage(404, "Not found", "There is nothing here.", "/manage/home", "Back");
}

const NOTES: Record<string, string> = {
  released: "Machine released. Activate the key on the new machine now.",
  sent: "Key sent to your email.",
  mailfail: "The email could not be sent right now. Try again in a few minutes.",
  portal: "The billing portal is not available right now. Try again in a few minutes.",
  missing: "That item was not found on your licences.",
};

export async function manageHome(req: Request, env: Env, deps: Deps, url: URL): Promise<Response> {
  const s = await session(req, env, deps);
  if (!s) return redirect("/manage");
  const m = url.searchParams.get("m") || "";
  const note = m === "limit" ? releaseLimitText(env) : NOTES[m] || "";
  const now = sec(deps);
  const lics = await licencesFor(env, s.email_hash);
  const csrf = `<input type="hidden" name="csrf" value="${esc(s.csrf)}">`;
  const cards = await Promise.all(lics.map(async (l) => {
    const offer = OFFERS[l.offer];
    const acts = (await env.DB.prepare("SELECT * FROM activations_v2 WHERE licence_id = ? AND released_at IS NULL ORDER BY created_at")
      .bind(l.id).all<Activation>()).results ?? [];
    const st = standing(l, now);
    const left = await releasesLeft(env, deps, l.id);
    const rows = acts.map((a) => `<tr><td><b>${esc(a.label)}</b><div class="muted">active since ${day(a.created_at)}` +
      `${a.last_renewed_at ? `, last checked ${day(a.last_renewed_at)}` : ""}</div></td><td style="text-align:right">` +
      `<form method="post" action="/manage/release">${csrf}<input type="hidden" name="activation_id" value="${esc(a.id)}">` +
      `<button type="submit"${left ? "" : " disabled"}>Release this machine</button></form></td></tr>`).join("");
    return `<div class="card"><h2 style="margin-top:0">${esc(offer.product)} <span class="muted">key …${esc(l.key_last4)}</span></h2>` +
      `<p>${st === "active" ? `<span class="ok">Active</span>, renews or ends ${day(l.lic_exp)}` : `<span class="bad">${st === "revoked" ? "Cancelled" : "Ended"}</span>`}` +
      ` · ${acts.length} of ${l.seats} ${l.seats === 1 ? "seat" : "seats"} in use</p>` +
      (rows ? `<table>${rows}</table>` : `<p class="muted">Not active on any machine yet.</p>`) +
      `<p class="muted">Releases left in the last 30 days: ${left} of 3. Releasing frees the seat so the key can be activated on another machine.</p>` +
      `<div class="row"><form method="post" action="/manage/resend">${csrf}<input type="hidden" name="licence_id" value="${esc(l.id)}"><button type="submit">Email me the key</button></form>` +
      `<form method="post" action="/manage/portal">${csrf}<input type="hidden" name="licence_id" value="${esc(l.id)}"><button type="submit">Billing and invoices</button></form></div></div>`;
  }));
  return page("Your Argus licences", `<h1>Your Argus licences</h1>` + (note ? `<div class="card">${esc(note)}</div>` : "") +
    (cards.join("") || `<p>No licences for this email.</p>`) +
    `<p class="muted">Need help? <a href="mailto:${esc(support(env))}">${esc(support(env))}</a></p>` +
    `<form method="post" action="/manage/signout">${csrf}<button type="submit">Sign out</button></form>`);
}

// ---------------------------------------------------------------------------------------------
// /link: approve `argus licence login` (a claim) from a browser, signed in by magic link
// ---------------------------------------------------------------------------------------------
export async function link(req: Request, env: Env, deps: Deps): Promise<Response> {
  const s = await session(req, env, deps);
  if (!s) return redirect("/manage?next=link");
  const lics = (await licencesFor(env, s.email_hash)).filter((l) => standing(l, sec(deps)) === "active");
  const csrf = `<input type="hidden" name="csrf" value="${esc(s.csrf)}">`;
  if (req.method === "GET") {
    const opts = lics.map((l) => `<label class="row"><input type="radio" name="licence_id" value="${esc(l.id)}" required> ${esc(OFFERS[l.offer].product)} (key …${esc(l.key_last4)})</label>`).join("");
    return page("Activate a machine", `<h1>Activate a machine</h1><p>Enter the code that <code>argus licence login</code> shows.</p>` +
      `<form method="post" action="/link">${csrf}<div class="row"><input type="text" name="code" required placeholder="XXXX-XXXX" autocomplete="off" aria-label="Code"></div>` +
      (opts || `<p class="bad">You have no active licence. <a href="/buy/argus-server">Buy Argus Server</a> or <a href="/buy/argus-desktop">Argus Desktop</a>.</p>`) +
      `<div class="row"><button class="primary" type="submit"${opts ? "" : " disabled"}>Activate</button></div></form>`);
  }
  if (!sameOrigin(req, env)) return simplePage(403, "Not allowed", "This form only works from this site.");
  const form = await formOf(req);
  if (!form || !constantTimeEqual(form.get("csrf") || "", s.csrf)) return simplePage(403, "Not allowed", "This page is out of date. Go back and reload it.");
  const lic = lics.find((l) => l.id === form.get("licence_id"));
  const code = normCode(form.get("code"));
  const claim = code.length === 8
    ? await env.DB.prepare("SELECT * FROM claims WHERE code_hash = ?").bind(await sha256Hex(code)).first<Claim>()
    : null;
  if (!lic || !claim || sec(deps) > claim.expires_at) return simplePage(400, "That code did not work", "Codes last 30 minutes. Run argus licence login again for a new one.", "/link", "Try again");
  const r = await bindClaim(env, deps, claim, lic, "owner");
  if (r === "expired" || r === "taken") return simplePage(400, "That code was already used", "Run argus licence login again for a new one.", "/link", "Try again");
  if (!r.ok) return simplePage(409, "No free seat", `This licence is in use on ${r.machines.map((m) => m.label).join(", ")}. Release that machine first.`, "/manage/home", "Manage your licence");
  return simplePage(200, "Machine activated", `“${claim.label}” is activated. The command on that machine finishes within a few seconds.`, "/manage/home", "See your licences");
}

