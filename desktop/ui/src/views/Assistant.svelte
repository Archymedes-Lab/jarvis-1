<script lang="ts">
  import { api } from "../lib/api";
  import { app, go, toast } from "../lib/store.svelte";
  import { t } from "../lib/words";
  import { tr, sev, agoT } from "../lib/i18n";

  let q = $state("");
  let answer = $state("");
  let source = $state("");
  let busy = $state(false);
  let needsLicence = $state(false);
  const prompts = $derived([tr("What needs me?"), tr("What's my score?"), tr("What changed today?")]);

  async function ask(text = q) {
    if (!text.trim() || busy) return;
    busy = true; answer = ""; source = ""; needsLicence = false;
    try { const r = await api.ask(text, app.mode, app.lang); answer = r.answer ?? r.message ?? ""; source = r.source ?? ""; }
    catch (e) { const m = String((e as Error).message ?? e); needsLicence = /licen[cs]e/i.test(m); toast(m, "bad"); }
    finally { busy = false; }
  }
  async function coach() {
    busy = true; answer = ""; source = "";
    try { const r = await api.scoreCoach(); answer = r.answer ?? ""; source = tr("score plan · deterministic"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
</script>

<div class="mx-auto flex max-w-[760px] flex-col gap-4">
  <div>
    <h2 class="text-heading-24">{t("nav.assistant")}</h2>
    <p class="mt-1 text-copy-14 text-gray-900">{t("assistant.sub")}</p>
  </div>
  <form class="card flex items-center gap-2 p-2" onsubmit={(e) => { e.preventDefault(); ask(); }}>
    <input class="input input-bare h-10 flex-1 text-copy-14" bind:value={q} maxlength="4000" placeholder={t("assistant.placeholder")} aria-label={tr("Question")} />
    <button class="btn btn-primary h-10 px-4" disabled={busy || !q.trim()}>{tr("Ask")}</button>
  </form>
  <div class="flex flex-wrap gap-2">
    {#each prompts as p}<button class="btn btn-sm" disabled={busy} onclick={() => { q = p; ask(p); }}>{p}</button>{/each}
    <button class="btn btn-sm" disabled={busy} onclick={coach}>{tr("How do I raise my score?")}</button>
  </div>
  {#if needsLicence}
    <div class="card flex items-center gap-3 p-5 text-copy-14">{tr("An ARGUS-INSTINCT licence is needed to ask questions.")}<button class="btn btn-sm ml-auto" onclick={() => go("pricing")}>{tr("See pricing")}</button></div>
  {/if}
  {#if busy}
    <div class="card p-5 text-copy-14 text-gray-900"><span class="dot dot-run mr-2"></span>{tr("Thinking…")}</div>
  {:else if answer}
    <div class="card selectable anim-rise p-5">
      <p class="text-copy-14 whitespace-pre-wrap">{answer}</p>
      {#if source && app.mode === "expert"}<p class="mt-3 text-label-12 text-gray-700">{source}</p>{/if}
    </div>
  {/if}
</div>
