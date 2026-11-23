import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { checkChar, checkKey } from "./licence";

const v = JSON.parse(readFileSync(new URL("../../../../tests/fixtures/licence/vectors.json", import.meta.url), "utf8"));

describe("licence key feedback", () => {
  test("matches the shared vectors", () => {
    for (const [body, check] of v.check) expect(checkChar(body)).toBe(check);
    for (const [input, canon] of v.parse) {
      const r = checkKey(input);
      if (canon) expect(r).toMatchObject({ state: "ok", key: canon });
      else expect(r.state).not.toBe("ok");
    }
  });
  test("explains a wrong check character, a wrong prefix, a stray character, and partial input", () => {
    const good = v.parse[0][1] as string;
    const typo = good.slice(0, -1) + (good.endsWith("0") ? "1" : "0");
    expect(checkKey(typo)).toMatchObject({ state: "bad", message: expect.stringContaining("check character") });
    expect(checkKey("ARGUS-SERVER-1C285B2D")).toMatchObject({ state: "bad", message: expect.stringContaining("ARGUS-SRV-") });
    expect(checkKey("ARGUS-SRV-0000U")).toMatchObject({ state: "bad", message: expect.stringContaining("“U”") });
    expect(checkKey("ARGUS-SRV-01234")).toMatchObject({ state: "typing" });
    expect(checkKey(`argus://activate?key=${good}`)).toMatchObject({ state: "ok", key: good });
  });
});
