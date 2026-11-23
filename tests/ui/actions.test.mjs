// Buttons that act on server-provided ids carry them in data-* attributes and
// go through the delegated click handler, never inside inline-handler
// JavaScript (where the browser decodes entities, so HTML escaping is moot).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./harness.mjs";

loadPage("jarvis/web/static/dashboard.html", ["esc"]);
const clicks = globalThis.__documentListeners.filter(([t]) => t === "click").map(([, f]) => f);

function click(dataset) {
  const button = { dataset };
  const target = { closest: (sel) => (sel === "[data-act]" ? button : null) };
  for (const f of clicks) f({ target, preventDefault() {} });
}

describe("delegated server-id actions", () => {
  it("passes a hostile id through verbatim as data, not as code", () => {
    const calls = [];
    globalThis.answerQuestion = (...a) => calls.push(["answer", ...a]);
    globalThis.runJob = (...a) => calls.push(["run", ...a]);
    globalThis.decideFix = (...a) => calls.push(["fix", ...a]);
    const hostile = "x');globalThis.__pwned=1;//";
    click({ act: "answer", id: hostile, choice: "yes" });
    click({ act: "runjob", job: hostile });
    click({ act: "fixdecide", id: hostile, choice: "reject" });
    assert.deepEqual(calls, [["answer", hostile, "yes"], ["run", hostile], ["fix", hostile, "reject"]]);
    assert.equal(globalThis.__pwned, undefined);
  });
});
