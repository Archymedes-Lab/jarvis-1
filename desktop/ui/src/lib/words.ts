// One vocabulary, two registers. Expert uses the product's own terms; Simple
// says the same thing in everyday words. Only wording differs: every number,
// path and severity stays what the daemon reported.
import { app } from "./store.svelte";
import { sev, tr } from "./i18n";

export const W = {
  // navigation
  "nav.overview": ["Home", "Overview"],
  "nav.findings": ["What I found", "Findings"],
  "nav.collectors": ["Checks", "Collectors"],
  "nav.review": ["Needs you", "Review"],
  "nav.assistant": ["Ask ARGUS-INSTINCT", "Assistant"],
  "nav.geo": ["Where am I", "GeoSecurity"],
  "nav.coverage": ["What Argus can see", "What Argus can see"],
  "nav.world": ["World events", "World"],
  "nav.procs": ["Running programs", "Processes"],
  "nav.phone": ["Alerts on my phone", "Phone"],
  "nav.pricing": ["Plan", "Pricing"],
  "nav.licence": ["Licence", "Licence"],
  "nav.settings": ["Settings", "Settings"],
  // severity: Simple says how soon, Expert keeps the daemon's level
  "sev.critical": ["Urgent", "Critical"],
  "sev.high": ["Look soon", "High"],
  "sev.medium": ["Worth a look", "Medium"],
  "sev.low": ["For your info", "Low"],
  // findings
  "findings.filter": ["Search what I found", "Filter findings"],
  "findings.none": ["Nothing to show.", "No findings."],
  // checks
  "checks.fresh": ["Up to date", "Fresh"],
  "checks.late": ["Behind or not started", "Late or never ran"],
  "checks.errors": ["Could not run", "Errors"],
  "checks.intro": ["ARGUS-INSTINCT looks at your computer in many small ways. Each one is a check.", ""],
  "checks.run": ["Check now", "Run"],
  // review
  "review.questions": ["Things ARGUS-INSTINCT is not sure about", "Questions"],
  "review.questions.sub": ["Tell ARGUS-INSTINCT whether these are things you expect on your computer. Your answer is only a note; nothing on your computer is changed.", "Your answer tells ARGUS-INSTINCT whether something is expected on this machine. It records intent; it changes nothing on the system."],
  "review.none": ["Nothing is waiting for you.", "No questions are waiting."],
  "review.fixes": ["Suggested fixes", "Fix proposals"],
  "review.fixes.sub": ["If you agree, ARGUS-INSTINCT looks into the problem and prepares a fix for you to read first. Nothing is applied from this app.", "Approving starts an investigation that drafts a patch for review. Applying a patch is never done from this app."],
  "review.cases": ["Groups to look at", "Cases"],
  "review.cases.sub": ["Things that look related are grouped, so one answer covers the whole group.", "Related findings are grouped, so one decision covers a group."],
  "review.recognise": ["Yes, that was me", "I recognise this"],
  "review.recognise.many": ["Yes, those were me", "I recognise these"],
  "review.unknown": ["No, that was not me", "I do not recognise this"],
  "review.unknown.many": ["No, those were not me", "I do not recognise these"],
  "review.more": ["Look closer", "Investigate more"],
  "review.approve": ["Let ARGUS-INSTINCT look into it", "Approve investigation"],
  "review.retry": ["Try again", "Retry draft"],
  "review.reject": ["No thanks", "Reject"],
  "review.auto": ["Handle long-standing items for me", "Auto-handle standing items"],
  // assistant
  "assistant.sub": ["Ask in your own words. ARGUS-INSTINCT answers from what it has seen on this computer and from a built-in guide to staying safe. It explains; it never changes anything.", "Answers come from ARGUS-INSTINCT's own data on this computer and a built-in safety guide. It reads; it never acts on what it says."],
  "assistant.placeholder": ["Ask anything, like “is my computer okay?”", "Ask anything about this machine"],
  // settings
  "settings.mode.sub": ["Simple uses everyday words and hides technical details. Expert shows everything ARGUS-INSTINCT knows.", "Simple explains things in everyday words and hides identifiers. Expert shows collectors, paths and evidence."],
  "settings.notify.findings": ["New important findings", "Critical and high findings"],
  "settings.notify.findings.sub": ["Show a pop-up when ARGUS-INSTINCT finds something that needs a look.", "Native notification for each new critical or high finding."],
  "settings.notify.health": ["When ARGUS-INSTINCT cannot see something", "Blind collectors and score drops"],
  "settings.notify.health.sub": ["Show a pop-up if one of the checks stops working or your score drops a lot.", "Native notification when a collector goes blind or the score crosses its gate."],
  "settings.notify.outage": ["If ARGUS-INSTINCT stops answering", "Daemon outage"],
  "settings.notify.outage.sub": ["Show a pop-up if the part that watches your computer stops responding, and when it is back.", "Native notification when the daemon is unreachable for a minute, and when it recovers."],
} as const;

export type Key = keyof typeof W;

/** The wording for the current level. Reads app.mode, so a template using it updates on switch. */
export function t(key: Key): string {
  const [simple, expert] = W[key];
  return tr(app.mode === "simple" ? simple : expert || simple);
}

/** A severity label in the current register; unknown levels keep their own name. */
export function sevWord(severity: string): string {
  const k = `sev.${severity}` as Key;
  return k in W ? t(k) : sev(severity);
}
