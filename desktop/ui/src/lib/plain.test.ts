import { expect, test } from "bun:test";
import { headline, plainFinding } from "./plain";

test("headline never says fine when something is critical, and admits partial coverage", () => {
  expect(headline(90, 0, 0, 0).tone).toBe("ok");
  expect(headline(90, 0, 0, 3).partial).toContain("incomplete");
  expect(headline(90, 0, 0, 0).partial).toBeUndefined();
  // Each part is a whole key, so every language translates it (a joined string never matched).
  expect(headline(10, 2, 0, 3).body.startsWith(" ")).toBe(false);
  expect(headline(10, 2, 5, 0).vars.n).toBe(2);
  expect(headline(10, 2, 5, 0).tone).toBe("bad");
  expect(headline(50, 0, 4, 0).tone).toBe("warn");
  expect(headline(undefined, 0, 0, 0).tone).toBe("unknown");
});

test("with nothing found the headline never claims the computer is fine or safe", () => {
  // The absence of alerts does not prove safety (Normal/Pro honesty rule, d50ac10).
  const ok = headline(95, 0, 0, 0);
  expect(ok.tone).toBe("ok");
  expect(`${ok.title} ${ok.body}`).not.toMatch(/\b(fine|safe|secure|protected|clean|healthy)\b/i);
  expect(ok.title).toContain("No signs");
});

test("plain wording uses the dashboard guide, and falls back without inventing a verdict", () => {
  const known = plainFinding({ severity: "high", title: "x", job: "j", category: "persistence" });
  expect(known.means.length).toBeGreaterThan(10);
  const other = plainFinding({ severity: "critical", title: "x", job: "j", category: "nope" });
  expect(other.why).toContain("seriously harm");
  expect(other.means).not.toMatch(/malware|compromised/i);
});

import { groupLabel, CATEGORY_LABEL } from "./plain";
test("a group always has a specific name, never the generic sentence", () => {
  expect(groupLabel("present")).toBe("Passwords and keys stored in plain text");
  expect(groupLabel("tracked")).not.toBe(groupLabel("present"));   // two groups, two names
  expect(groupLabel("weird thing")).toBe("Weird thing");
  expect(groupLabel(null)).toBe(CATEGORY_LABEL[""]);
  for (const v of Object.values(CATEGORY_LABEL)) expect(v).not.toContain("noticed something");
});
