// The dashboard's markup reaches code only through the UI_CALLS table: a
// data-click / data-enter / data-change / data-submit attribute names an entry.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./harness.mjs";

const { markup } = loadPage("jarvis/web/static/dashboard.html", ["esc"]);
const listeners = globalThis.__documentListeners;
const fire = (type, el, extra = {}) => {
  const target = { closest: (sel) => (sel === `[data-${{ click: "click", input: "input",
    change: "change", submit: "submit", keydown: "enter" }[type]}]` ? el : null) };
  for (const [t, f] of listeners) if (t === type) f({ target, ...extra });
};
const elem = (attrs, dataset = {}) => ({ dataset, parentElement: null, getAttribute: (a) => attrs[a] });

describe("dashboard wiring", () => {
  it("routes clicks, Enter, changes and submits to the named function with its argument", () => {
    const calls = [];
    globalThis.setTheme = (t) => calls.push(["theme", t]);
    globalThis.setSev = (s) => calls.push(["sev", s]);
    globalThis.onFilter = () => calls.push(["filter"]);
    globalThis.askJarvis = (ev) => calls.push(["ask", ev.kind]);
    fire("click", elem({ "data-click": "theme" }, { arg: "dark" }));
    fire("keydown", elem({ "data-enter": "sev" }, { arg: "" }), { key: "Enter" });
    fire("keydown", elem({ "data-enter": "sev" }, { arg: "high" }), { key: "a" });
    fire("change", elem({ "data-change": "filter" }));
    fire("submit", elem({ "data-submit": "ask" }), { kind: "submit" });
    fire("click", elem({ "data-click": "no-such-entry" }));
    assert.deepEqual(calls, [["theme", "dark"], ["sev", null], ["filter"], ["ask", "submit"]]);
  });

  it("every data-click/-input/-change/-submit/-enter name in the page has an entry", () => {
    const { page } = loadPage("jarvis/web/static/dashboard.html", ["UI_CALLS"]);
    const { html } = loadPage("jarvis/web/static/dashboard.html", ["esc"]);
    const names = [...html.matchAll(/data-(?:click|input|change|submit|enter)="([a-z]+)"/g)].map((m) => m[1]);
    assert.ok(names.length > 30, names.length);
    for (const n of names) assert.ok(n in page.UI_CALLS, n);
    assert.doesNotMatch(markup, /\son[a-z]+=/);
  });
});
