// UI tests: the new Continuity and Activity cards render honest state.
//
// These run the page's own functions (not copies) against stubbed DOM:
// a violated invariant must read VIOLATED, attacker-controlled text must
// be escaped, and the static contract (ids + render wiring) must hold.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./harness.mjs";

const { html, page } = loadPage("jarvis/web/static/dashboard.html",
  ["continuityHTML", "activityHTML", "esc", "renderHealth", "scoreTrendHTML", "renderReviewQueue", "wakeHTML"]);

describe("score card", () => {
  const nodes = new Map();
  const mount = () => {
    nodes.clear();
    document.getElementById = (id) => {
      if (!nodes.has(id)) nodes.set(id, {innerHTML: "", textContent: ""});
      return nodes.get(id);
    };
  };
  const verifiedArea = {name: "Network", score: 100, open: {}, blind: []};
  const liveArea = {name: "Network", score: 0, open: {}, blind: [{job: "netwatch", state: "stale"}]};
  const waking = (extra = {}) => ({security: {
    score: 66, grade: "needs work", coverage: 100, state: "verifying", phase: "waking",
    verified_at: 1700000000, warmup_since: 1700014400, warmup_ends: 1700016200,
    history: [[1700000000, 66]], areas: [verifiedArea], next_steps: [],
    progress: {checked: 30, total: 53, pending: ["netwatch"], retrying: [], running: ["sysmon"], ...extra},
    live: {score: 10, coverage: 57, observed: 30, jobs: 53, areas: [liveArea], next_steps: []},
  }});

  it("holds the last verified score while waking and shows progress, not the partial sweep", () => {
    mount();
    page.renderHealth(waking());
    const card = nodes.get("health").innerHTML;
    assert.match(card, />66<\/b><span>last verified/);
    assert.doesNotMatch(card, />10<\/b>/);
    assert.match(card, /Waking up/);
    assert.match(card, /<b>30\/53<\/b> current/);
    assert.match(card, /now running: sysmon/);
    assert.match(card, /re-checking/);
    assert.doesNotMatch(card, /steady over 24h/);
    assert.match(nodes.get("wins").innerHTML, /Re-verifying collectors/);
    assert.match(nodes.get("healthsub").textContent, /waking up/);
  });

  it("names collectors that failed since waking", () => {
    mount();
    page.renderHealth(waking({retrying: ["intrusion", "memscan"]}));
    assert.match(nodes.get("health").innerHTML, /failed since waking, retrying: intrusion, memscan/);
  });

  it("escapes collector names in the progress panel", () => {
    const out = page.wakeHTML(waking({running: ["<img src=x>"]}).security, 1700014500);
    assert.doesNotMatch(out, /<img src=x>/);
    assert.match(out, /live score applies in ≤29 min/);
  });
});

describe("continuity card", () => {
  it("reports absence instead of a false green", () => {
    assert.match(page.continuityHTML(null), /not reporting/);
  });

  it("marks violated invariants VIOLATED with their reason", () => {
    const out = page.continuityHTML({
      invariants: { ok: false,
        freshness: { ok: false, reason: "stale with no recovery" },
        privacy: { ok: true, reason: "local" } },
      governor: { pressured: false, reason: "nominal" },
      perception: null,
    });
    // Sentence case since the 2026-10-22 design system; the state is what matters.
    assert.match(out, /title="violated"[^]*>Violated</);
    assert.match(out, /stale with no recovery/);
    assert.match(out, /holding/i);
  });

  it("shows governor deferral and perception counts", () => {
    const out = page.continuityHTML({
      invariants: { ok: true },
      governor: { pressured: true, reason: "CPU 88%" },
      perception: { verified: 41, unreconciled: 2, unknown: 7,
                    windows_processes: 50 },
    });
    assert.match(out, /deferring noncritical/);
    assert.match(out, /41 verified/);
  });

  it("escapes attacker-controlled text", () => {
    const out = page.continuityHTML({
      invariants: { ok: false,
        privacy: { ok: false, reason: '<img src=x onerror="1">' } },
      governor: {}, perception: null,
    });
    assert.doesNotMatch(out, /<img/);
    assert.match(out, /&lt;img/);
  });
});

describe("activity card", () => {
  it("stays quiet with no stories instead of inventing them", () => {
    assert.match(page.activityHTML([]), /no correlated activity/);
  });

  it("renders one story per chain with severity and provenance", () => {
    const out = page.activityHTML([{
      headline: "2 related observations across network, sysmon: evil",
      worst_severity: "high", count: 2, jobs: ["network", "sysmon"],
      host: "win", causal: false, last: 1700000000, member_overflow: 0,
    }]);
    assert.match(out, /evil/);
    assert.match(out, /causality unverified/);
    assert.match(out, /pill high/);
  });

  it("marks explicit causal edges and overflow honestly", () => {
    const out = page.activityHTML([{
      headline: "chain", worst_severity: "critical", count: 9,
      jobs: ["sysmon"], host: "win", causal: true, last: null,
      member_overflow: 3,
    }]);
    assert.match(out, /causal edge/);
    assert.match(out, /\+3 more/);
  });
});

describe("static wiring contract", () => {
  for (const id of ["continuity", "contcnt", "activity", "actcnt",
                    "continuitycard", "activitycard"]) {
    it(`dashboard contains #${id}`, () => {
      assert.ok(html.includes(`id="${id}"`), `missing #${id}`);
    });
  }
  it("render() mounts both cards", () => {
    assert.ok(html.includes("renderContinuity(s)"));
    assert.ok(html.includes("renderActivity(s)"));
  });
});

describe("score trend", () => {
  const now = 1700086400;
  it("waits for two in-window samples instead of drawing a false line", () => {
    const t = page.scoreTrendHTML([[now - 90000, 40], [now - 60, 70]], now);
    assert.equal(t.count, 1);
    assert.match(t.html, /Not enough verified score samples/);
  });
  it("drops malformed and out-of-range samples and plots the rest in order", () => {
    const t = page.scoreTrendHTML([[now - 60, 70], [now - 3600, 67], ["x", 5],
      [now - 120, 140], [now + 600, 90]], now);
    assert.equal(t.count, 2);
    assert.equal(t.latest, 70);
    assert.match(t.html, /from 67 to 70 percent/);
  });
});

describe("load resilience", () => {
  it("state polling is single-flight and time-bounded", () => {
    assert.match(html, /if \(paused \|\| tickPending\) return;/);
    assert.match(html, /signal: ctl\.signal/);
    assert.match(html, /tickPending = false;/);
    assert.ok(html.includes('id="loadnotice"'));
  });
  it("findings render in bounded batches and skip identical rebuilds", () => {
    assert.match(html, /rows\.slice\(0, findingLimit\)/);
    assert.match(html, /if \(html === lastFindingRender\) return;/);
  });
});

describe("review queue", () => {
  it("names waiting decisions in the collapsed header and flags it", () => {
    const nodes = new Map(); let flagged = null;
    document.getElementById = (id) => {
      if (!nodes.has(id)) nodes.set(id, {innerHTML: "", textContent: "", open: false,
        classList: {toggle: (c, on) => { if (c === "needs") flagged = on; }}});
      return nodes.get(id);
    };
    page.renderReviewQueue({questions: [{}, {}], fix: [{}]});
    assert.equal(nodes.get("reviewcount").textContent, "2 need your answer · 1 fix proposal");
    assert.equal(flagged, true);
    page.renderReviewQueue({questions: [], fix: []});
    assert.match(nodes.get("reviewcount").textContent, /^no questions waiting/);
    assert.equal(flagged, false);
  });
});
