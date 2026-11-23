<script lang="ts">
  import Pill from "../components/Pill.svelte";
  import { api } from "../lib/api";
  import { app, refresh, toast } from "../lib/store.svelte";
  import { groupQuestions, noteText } from "../lib/model";
  import { t } from "../lib/words";
  import { tr, sev, agoT } from "../lib/i18n";
  import { onMount } from "svelte";
  import type { Autopilot } from "../lib/api";

  // Autopilot groups related findings into one case, so a decision covers a
  // group instead of one question per item. Older daemons do not have it.
  let ap = $state<Autopilot | null>(null);
  async function loadCases() { try { ap = await api.autopilot(); } catch { ap = null; } }
  onMount(loadCases);
  const allCases = $derived(ap?.needs_me ?? []);
  // Simple: one decision at a time (skip moves on). Expert: the first ten, then more.
  let caseStep = $state(0);
  let caseLimit = $state(10);
  const cases = $derived(app.mode === "simple"
    ? allCases.slice(caseStep % Math.max(1, allCases.length), (caseStep % Math.max(1, allCases.length)) + 1)
    : allCases.slice(0, caseLimit));
  let caseBusy = $state("");
  async function decideCase(key: string, choice: "recognise" | "not_recognise" | "investigate_further") {
    caseBusy = key;
    try { await api.decideCase(key, choice); toast(tr("Decision recorded"), "ok"); await Promise.all([loadCases(), refresh()]); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { caseBusy = ""; }
  }
  async function toggleAuto() {
    if (!ap?.policy) return;
    const on = !ap.policy.auto_handle;
    try { await api.setAutoHandle(on); toast(on ? tr("Auto-handle is on") : tr("Auto-handle is off"), "ok"); await loadCases(); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
  }

  const allGroups = $derived(groupQuestions(app.data?.questions ?? []));
  let step = $state(0);
  const groups = $derived(app.mode === "simple" ? allGroups.slice(step % Math.max(1, allGroups.length), (step % Math.max(1, allGroups.length)) + 1) : allGroups);
  const fixes = $derived((app.data?.fix ?? []) as any[]);
  let busy = $state(false);
  // A grouped question answers every item in it, so a multi-item answer asks
  // once more before it is sent. Neither answer is styled as the default.
  let pending = $state<{ prompt: string; choice: "yes" | "no" } | null>(null);
  function choose(g: { prompt: string; ids: { id: string }[] }, choice: "yes" | "no") {
    if (g.ids.length > 1 && !(pending?.prompt === g.prompt && pending.choice === choice)) { pending = { prompt: g.prompt, choice }; return; }
    pending = null; answer(g.ids, choice);
  }

  async function answer(ids: { id: string }[], choice: "yes" | "no") {
    busy = true;
    try {
      for (const q of ids) await api.answer(q.id, choice);
      toast(ids.length > 1 ? tr("Answer recorded for {n} questions", { n: ids.length }) : tr("Answer recorded"), "ok");
      await refresh();
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  async function decide(id: string, d: "approve" | "retry" | "reject") {
    busy = true;
    try { const r = await api.decideFix(id, d); toast(r.message ?? tr("Decision recorded"), "ok"); await refresh(); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
</script>

<div class="flex flex-col gap-8">
  {#if ap}
  <section>
    <div class="mb-1 flex items-center gap-3">
      <h2 class="text-heading-20">{t("review.cases")}</h2>
      {#if ap.policy}
        <label class="ml-auto flex items-center gap-2 text-copy-13">
          <input type="checkbox" checked={ap.policy.auto_handle} onchange={toggleAuto} />
          {t("review.auto")}
        </label>
      {/if}
    </div>
    <p class="mb-4 text-copy-13 text-gray-900">{t("review.cases.sub")}
      {#if ap.policy?.auto_handle}{app.mode === "simple" ? tr("If nothing changes for {n} days, small items that only need your OK are accepted for you and written down. Urgent items always wait for you.", { n: ap.policy.min_age_days }) : tr("Auto-handle is on: after {n} unchanged days, items that only need your OK are accepted and logged. Never critical.", { n: ap.policy.min_age_days })}{/if}</p>
    {#if !cases.length}
      <div class="card empty">{tr("No cases need a decision.")}</div>
    {:else}
      {#if app.mode === "simple" && allCases.length > 1}
        <p class="mb-3 text-copy-13 text-gray-900">{tr("Question {i} of {n}.", { i: (caseStep % allCases.length) + 1, n: allCases.length })} <button class="link" onclick={() => caseStep++}>{tr("Skip for now")}</button></p>
      {/if}
      <div class="flex flex-col gap-3">
        {#each cases as c (c.key)}
          <div class="card p-5">
            <div class="flex items-center gap-2"><Pill severity={c.severity} /><span class="text-copy-13 text-gray-900">{app.mode === "simple" ? (c.count === 1 ? tr("Seen 1 time") : tr("Seen {n} times", { n: c.count })) : c.count === 1 ? tr("1 observation") : tr("{n} observations", { n: c.count })}</span></div>
            <p class="selectable mt-2.5 text-label-14">{c.title}</p>
            {#if app.mode === "expert"}<p class="selectable mt-1 text-copy-13 text-gray-900">{c.what_happened}</p>{/if}
            {#if c.recommended}<p class="selectable mt-1 text-copy-13">{c.recommended}</p>{/if}
            {#if noteText(c.ai_note)}
              <details class="mt-2 text-copy-13 text-gray-900"><summary class="cursor-default text-label-12 text-gray-900">{tr("Details")}</summary>
                <p class="selectable mt-1">{noteText(c.ai_note)}</p></details>
            {/if}
            <div class="mt-4 flex flex-wrap gap-2">
              <button class="btn" disabled={!!caseBusy} onclick={() => decideCase(c.key, "recognise")}>{c.count > 1 ? t("review.recognise.many") : t("review.recognise")}</button>
              <button class="btn" disabled={!!caseBusy} onclick={() => decideCase(c.key, "not_recognise")}>{c.count > 1 ? t("review.unknown.many") : t("review.unknown")}</button>
              <button class="btn btn-ghost" disabled={!!caseBusy} onclick={() => decideCase(c.key, "investigate_further")}>{t("review.more")}</button>
            </div>
          </div>
        {/each}
      </div>
      {#if app.mode === "expert" && allCases.length > caseLimit}
        <div class="mt-3 text-center"><button class="btn btn-sm" onclick={() => (caseLimit += 10)}>{tr("Show {n} more", { n: Math.min(10, allCases.length - caseLimit) })}</button></div>
      {/if}
    {/if}
  </section>
  {/if}

  <section>
    <h2 class="mb-1 text-heading-20">{t("review.questions")}</h2>
    <p class="mb-4 text-copy-13 text-gray-900">{t("review.questions.sub")}</p>
    {#if !groups.length}
      <div class="card empty">{t("review.none")}</div>
    {:else}
      {#if app.mode === "simple" && allGroups.length > 1}
        <p class="mb-3 text-copy-13 text-gray-900">{tr("Question {i} of {n}.", { i: (step % allGroups.length) + 1, n: allGroups.length })} <button class="link" onclick={() => step++}>{tr("Skip for now")}</button></p>
      {/if}
      <div class="flex flex-col gap-3">
        {#each groups as g (g.prompt)}
          {@const q = g.ids[0]}
          <div class="card p-5">
            <div class="flex items-center gap-2"><Pill severity={g.severity ?? "low"} />
              {#if g.ids.length > 1}<span class="text-copy-13 text-gray-900">{tr("asked about {n} items", { n: g.ids.length })}</span>{/if}</div>
            <p class="selectable mt-2.5 text-label-14">{g.prompt}</p>
            {#if pending?.prompt === g.prompt}
              <div class="mt-4 flex flex-wrap items-center gap-2 rounded-lg bg-gray-100 px-3 py-2">
                <span class="text-copy-13">{tr("Answer {choice} for all {n} items?", { choice: pending.choice === "yes" ? tr("Yes") : tr("No"), n: g.ids.length })}</span>
                <button class="btn btn-sm ml-auto" disabled={busy} onclick={() => choose(g, pending!.choice)}>{tr("Confirm for {n}", { n: g.ids.length })}</button>
                <button class="btn btn-ghost btn-sm" onclick={() => (pending = null)}>{tr("Cancel")}</button>
              </div>
            {:else}
              <div class="mt-4 flex flex-wrap gap-2">
                <button class="btn" disabled={busy} onclick={() => choose(g, "yes")}>{tr("Yes")}{q.yes ? ` · ${q.yes}` : ""}</button>
                <button class="btn" disabled={busy} onclick={() => choose(g, "no")}>{tr("No")}{q.no ? ` · ${q.no}` : ""}</button>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </section>

  <section>
    <h2 class="mb-1 text-heading-20">{t("review.fixes")}</h2>
    <p class="mb-4 text-copy-13 text-gray-900">{t("review.fixes.sub")}</p>
    {#if !fixes.length}
      <div class="card empty">{tr("No fix proposals.")}</div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each fixes as f (f.id)}
          <div class="card p-5">
            {#if app.mode === "expert"}<div class="flex items-center gap-2"><span class="pill pill-info">{f.status}</span><span class="tag">{f.id}</span></div>{/if}
            <p class="selectable mt-2.5 text-label-14">{f.title}</p>
            {#if f.problem}<p class="selectable mt-1 text-copy-13 text-gray-900">{f.problem}</p>{/if}
            {#if f.generation_error && app.mode === "expert"}<p class="mt-1 text-copy-13 text-amber-900">{tr("Draft failed: {error}", { error: f.generation_error })}</p>{/if}
            <div class="mt-4 flex flex-wrap gap-2">
              {#if f.status === "proposed"}<button class="btn btn-primary" disabled={busy} onclick={() => decide(f.id, "approve")}>{t("review.approve")}</button>{/if}
              {#if f.status === "draft_failed"}<button class="btn btn-primary" disabled={busy} onclick={() => decide(f.id, "retry")}>{t("review.retry")}</button>{/if}
              <button class="btn" disabled={busy} onclick={() => decide(f.id, "reject")}>{t("review.reject")}</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </section>
</div>
