// Opt-in blocking of session recorders and tracking pixels, with per-site
// exceptions. Shared by the service worker and the options page.
//
// Safety contract (tested in tests/test_veil_blocking.py):
//   * both rulesets ship disabled; nothing is blocked until the owner opts in
//   * no rule can block a top-level page or a frame, so links and navigation
//     always work and the worst case is a missing survey or chat widget
//   * a site on the allow list gets every request through, whatever else is on
//   * turning a ruleset off, or removing the extension, undoes it completely
export const RULESETS = ["replay", "pixels"];
export const ALLOW_PRIORITY = 100;
const ALLOW_BASE = 1000;
const MAX_SITES = 200;
const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

// Lower-case host names only; anything else is dropped rather than guessed at.
export function cleanSites(text) {
  const out = [];
  for (const raw of String(text || "").split(/[\s,]+/)) {
    let site = raw.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/[/:].*$/, "").replace(/^\*\./, "");
    if (HOST.test(site) && !out.includes(site)) out.push(site);
    if (out.length >= MAX_SITES) break;
  }
  return out;
}

export function allowRules(sites) {
  return cleanSites(sites.join(" ")).map((site, i) => ({
    id: ALLOW_BASE + i, priority: ALLOW_PRIORITY,
    action: {type: "allowAllRequests"},
    condition: {requestDomains: [site], resourceTypes: ["main_frame", "sub_frame"]},
  }));
}

const LABELS = {replay: "session recorders", pixels: "tracking pixels"};

export function stateTitle(enabled) {
  return enabled.length
    ? "JARVIS Veil: blocking " + enabled.map((id) => LABELS[id]).join(" and ") + ". Click to change or turn off."
    : "JARVIS Veil: not blocking anything. Click to change.";
}

// `blocking` is {replay: bool, pixels: bool, allow: [site]} as stored.
export async function applyBlocking(api, blocking) {
  const dnr = api.declarativeNetRequest;
  const enable = RULESETS.filter((id) => blocking[id] === true);
  const disable = RULESETS.filter((id) => blocking[id] !== true);
  await dnr.updateEnabledRulesets({enableRulesetIds: enable, disableRulesetIds: disable});
  const existing = (await dnr.getDynamicRules()).map((r) => r.id);
  await dnr.updateDynamicRules({removeRuleIds: existing, addRules: allowRules(blocking.allow || [])});
  if (dnr.setExtensionActionOptions) {
    // The toolbar badge counts what was blocked on the current tab.
    await dnr.setExtensionActionOptions({displayActionCountAsBadgeText: enable.length > 0});
  }
  if (api.action && api.action.setTitle) {
    // The badge is empty until something is blocked, so the tooltip always
    // states whether blocking is on; a click opens the switch (background.js).
    await api.action.setTitle({title: stateTitle(enable)});
  }
  return {enabled: enable};
}
