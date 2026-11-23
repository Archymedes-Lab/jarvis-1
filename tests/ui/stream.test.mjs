// UI tests: the dashboard's live pulse client (/api/stream).
//
// The stream only decides *when* to refresh; polling stays as the floor.
// These drive the page's own startStream() with a fake EventSource: a pulse
// change refreshes, the poll relaxes while the stream is up and returns to
// 5 s the moment it drops, and a refused stream is retried later.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./harness.mjs";

const sources = [];
class FakeEventSource {
  constructor(url) { this.url = url; this.readyState = 0; this.handlers = {}; sources.push(this); }
  addEventListener(name, fn) { this.handlers[name] = fn; }
  pulse(p) { this.handlers.pulse({ data: JSON.stringify(p) }); }
  fail(state) { this.readyState = state; this.onerror && this.onerror(); }
}
globalThis.EventSource = FakeEventSource;

const { page } = loadPage("jarvis/web/static/dashboard.html", ["startStream"]);

function harness() {
  const polls = [], ticks = [], later = [];
  globalThis.setInterval = (fn, ms) => { polls.push(ms); return polls.length; };
  globalThis.clearInterval = () => {};
  globalThis.setTimeout = (fn, ms) => { later.push({ fn, ms }); return 0; };
  globalThis.tick = () => ticks.push(1);
  return { polls, ticks, later };
}

describe("live pulse stream", () => {
  it("connects to /api/stream at load", () => {
    assert.equal(sources[0].url, "/api/stream");
  });

  it("refreshes on change only, relaxes the poll, and restores it on a drop", () => {
    const { polls, ticks } = harness();
    const es = page.startStream();
    es.pulse({ version: "a", score: 91 });
    // The first pulse after load only arms the stream; the page just loaded.
    assert.equal(ticks.length, 0);
    assert.deepEqual(polls, [30000]);
    es.pulse({ version: "a" });
    assert.equal(ticks.length, 0);
    es.pulse({ version: "b" });
    assert.equal(ticks.length, 1);
    es.fail(0);                       // dropped; EventSource will reconnect
    assert.deepEqual(polls, [30000, 5000]);
    assert.equal(ticks.length, 2);    // and state is refreshed immediately
  });

  it("a refused stream falls back to polling and retries later", () => {
    const { polls, later } = harness();
    const es = page.startStream();
    es.fail(2);                       // CLOSED: 503 / 403, no auto-reconnect
    assert.deepEqual(polls, []);      // never relaxed, 5 s poll untouched
    assert.equal(later.length, 1);
    assert.equal(later[0].ms, 60000);
  });

  it("malformed pulses are ignored, not trusted", () => {
    const { polls, ticks } = harness();
    const es = page.startStream();
    es.handlers.pulse({ data: "{not json" });
    assert.deepEqual(polls, []);
    assert.equal(ticks.length, 0);
  });
});
