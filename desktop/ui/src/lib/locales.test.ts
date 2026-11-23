import { expect, test } from "bun:test";
import { allKeys } from "../../scripts/i18n-all";
import fr from "./locales/fr.json";
import de from "./locales/de.json";
import es from "./locales/es.json";
import zh from "./locales/zh.json";
import ja from "./locales/ja.json";
import ko from "./locales/ko.json";
import pt from "./locales/pt.json";
import hi from "./locales/hi.json";
import ru from "./locales/ru.json";
import ar from "./locales/ar.json";

const LOCALES: Record<string, Record<string, string>> = { fr, de, es, zh, ja, ko, pt, hi, ru, ar };
const placeholders = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join(",");

test("every language has every interface string", () => {
  const keys = allKeys();
  expect(keys.length).toBeGreaterThan(250);
  for (const [lang, table] of Object.entries(LOCALES)) {
    const missing = keys.filter((k) => !(k in table));
    expect({ lang, missing }).toEqual({ lang, missing: [] });
  }
});

test("no translation is blank, and each keeps the same {placeholders}", () => {
  for (const [lang, table] of Object.entries(LOCALES)) {
    for (const [en, local] of Object.entries(table)) {
      expect(local.trim().length, `${lang}: ${en}`).toBeGreaterThan(0);
      expect(placeholders(local), `${lang}: ${en}`).toBe(placeholders(en));
    }
  }
});

test("the product name is never translated", () => {
  for (const [lang, table] of Object.entries(LOCALES)) {
    for (const [en, local] of Object.entries(table)) {
      if (en.includes("ARGUS-INSTINCT")) expect(local, `${lang}: ${en}`).toContain("ARGUS-INSTINCT");
    }
  }
});

test("no table has strings that the interface no longer uses", () => {
  const keys = new Set(allKeys());
  for (const [lang, table] of Object.entries(LOCALES)) {
    const stale = Object.keys(table).filter((k) => !keys.has(k));
    expect({ lang, stale }).toEqual({ lang, stale: [] });
  }
});
