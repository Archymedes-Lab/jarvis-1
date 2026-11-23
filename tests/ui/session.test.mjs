// session.js: a browser without an API session is sent to /pair once, and only
// for the server's "token" refusal on an /api/ route.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..",
  "jarvis/web/static/session.js"), "utf8");

function load({ status = 200, body = {}, framed = false, path = "/coverage" } = {}) {
  const went = [];
  const win = {};
  win.window = win;
  win.top = framed ? {} : win;
  win.location = { href: "http://localhost:8787" + path, pathname: path, assign: (u) => went.push(u) };
  win.fetch = async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  win.EventSource = undefined;
  new Function("window", "location", "URL", "Response", SRC)(win, win.location, URL, Response);
  return { win, went };
}

describe("session redirect", () => {
  it("sends a token refusal on an /api/ route to /pair with the way back", async () => {
    const { win, went } = load({ status: 403, body: { error: "missing or wrong API token" } });
    const r = await win.fetch("/api/coverage");
    assert.equal(r.status, 403);
    await win.fetch("/api/state");
    assert.deepEqual(went, ["/pair?next=%2Fcoverage"]);          // once, not twice
  });
  for (const [why, opts, url] of [
    ["another 403", { status: 403, body: { error: "cross-site request" } }, "/api/state"],
    ["a success", { status: 200, body: {} }, "/api/state"],
    ["a non-API route", { status: 403, body: { error: "token" } }, "/static/x.json"],
    ["a framed page", { status: 403, body: { error: "token" }, framed: true }, "/api/geo"],
    ["the pairing page itself", { status: 403, body: { error: "token" }, path: "/pair" }, "/api/state"],
  ]) {
    it(`stays put on ${why}`, async () => {
      const { win, went } = load(opts);
      await win.fetch(url);
      assert.deepEqual(went, []);
    });
  }
});
