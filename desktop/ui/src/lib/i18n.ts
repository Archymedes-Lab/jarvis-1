// Interface language. English text in the source is the key: tr("Open review")
// returns the chosen language's wording, or the English itself when a language
// has no entry (never blank, never a raw key). {name} placeholders are filled
// from `vars`. The daemon's own text (finding titles, evidence, questions) is
// shown as the daemon sent it; only the assistant's model replies follow the
// chosen language.
import { app } from "./store.svelte";
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

export const LANGS = [
  { code: "en", name: "English", english: "English" },
  { code: "fr", name: "Français", english: "French" },
  { code: "de", name: "Deutsch", english: "German" },
  { code: "es", name: "Español", english: "Spanish" },
  { code: "zh", name: "中文（简体）", english: "Simplified Chinese" },
  { code: "ja", name: "日本語", english: "Japanese" },
  { code: "ko", name: "한국어", english: "Korean" },
  { code: "pt", name: "Português (Brasil)", english: "Brazilian Portuguese" },
  { code: "hi", name: "हिन्दी", english: "Hindi" },
  { code: "ru", name: "Русский", english: "Russian" },
  { code: "ar", name: "العربية", english: "Arabic" },
] as const;
export type Lang = (typeof LANGS)[number]["code"];

const TABLES: Record<string, Record<string, string>> = { fr, de, es, zh, ja, ko, pt, hi, ru, ar };

export function tr(text: string, vars?: Record<string, string | number>): string {
  const hit = TABLES[app.lang]?.[text];
  const out = hit || text;
  return vars ? out.replace(/\{(\w+)\}/g, (_, k) => String(vars[k] ?? "")) : out;
}

/** "5m ago" in the chosen language (model.ts stays English and pure). */
export function agoT(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return tr("never");
  const d = Math.max(0, Math.floor(now - ts));
  if (d < 60) return tr("{n}s ago", { n: d });
  if (d < 3600) return tr("{n}m ago", { n: Math.floor(d / 60) });
  if (d < 86400) return tr("{n}h ago", { n: Math.floor(d / 3600) });
  return tr("{n}d ago", { n: Math.floor(d / 86400) });
}

export const sev = (s: string) => tr(s ? s[0].toUpperCase() + s.slice(1) : s);

export function langName(code: string): string {
  return LANGS.find((l) => l.code === code)?.english ?? "English";
}
