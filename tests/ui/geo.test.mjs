// UI tests: the accuracy-aware geo view drives the camera honestly.
//
// A tight fix opens close, a loose fix opens wide, and no position stays
// global — the camera must follow the backend's view verdict, and place()
// must actually consult it rather than a hardcoded height.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadPage } from "./harness.mjs";

const { html, page } = loadPage("jarvis/web/static/geo.html", ["viewHeight"]);

describe("viewHeight", () => {
  it("opens street scale for tight fixes", () => {
    assert.equal(page.viewHeight({ mode: "street", zoom: 16 }), 1500);
  });
  it("opens city scale for loose fixes", () => {
    assert.equal(page.viewHeight({ mode: "city", zoom: 11 }), 60000);
  });
  it("stays global without a position", () => {
    assert.equal(page.viewHeight({ mode: "globe", zoom: 2 }), 2.2e6);
  });
  it("falls back to global on unknown input, never crashes", () => {
    assert.equal(page.viewHeight(null), 2.2e6);
    assert.equal(page.viewHeight({}), 2.2e6);
  });
});

describe("static wiring contract", () => {
  it("place() consults the view verdict instead of a hardcoded height", () => {
    assert.ok(html.includes("viewHeight(payload.view)"));
  });
  it("panel shows the view mode and its reason", () => {
    assert.ok(html.includes("v.mode"));
    assert.ok(html.includes("v.reason"));
  });
});
