<script lang="ts">
  import { brand } from "../lib/brand";
  import { Dialog } from "bits-ui";
  import X from "@lucide/svelte/icons/x";
  import Search from "@lucide/svelte/icons/search";
  import Pill from "../components/Pill.svelte";
  import Segmented from "../components/Segmented.svelte";
  import Select from "../components/Select.svelte";
  import { app } from "../lib/store.svelte";
  import { tr, agoT } from "../lib/i18n";
  import { sevWord, t } from "../lib/words";
  import { groupLabel, hasGuide, plainFinding } from "../lib/plain";
  import { findingsView, sentence, SEVERITIES, type Finding } from "../lib/model";

  const all = $derived((app.data?.findings ?? []) as Finding[]);
  // One counting rule with Home (model.findingsView): the number on each severity is the rows it lists.
  const view = $derived(findingsView(all, { query: app.query, severity: app.severity, host: app.host, job: app.job }));
  const counts = $derived(view.counts);
  const rows = $derived(view.rows);
  const jobs = $derived([...new Set(all.map((f) => f.job))].sort());
  let limit = $state(150);
  $effect(() => { app.query; app.severity; app.host; app.job; limit = 150; });
  const filtered = $derived(!!(app.query || app.severity || app.host || app.job));
  function clear() { app.query = ""; app.severity = null; app.host = ""; app.job = ""; }
  // The toggle group's empty value means "all severities".
  let sev = $state(app.severity ?? "");
  $effect(() => { sev = app.severity ?? ""; });
  $effect(() => { app.severity = sev || null; });
  const sevItems = $derived([{ value: "", label: tr("All"), count: all.length },
    ...SEVERITIES.map((s) => ({ value: s, label: sevWord(s), count: counts[s], tone: s === "critical" && counts[s] ? "text-amber-900" : undefined }))]);
  const hostItems = $derived( [{ value: "", label: tr("Both hosts") }, { value: "win", label: "Windows" }, { value: "wsl", label: "WSL" }]);
  const jobItems = $derived([{ value: "", label: tr("All collectors") }, ...jobs.map((j) => ({ value: j, label: j }))]);
  // Simple groups the list by kind, so a long list reads as a few plain sentences.
  const groups = $derived.by(() => {
    const by = new Map<string, { category: string; count: number; worst: string; sample: Finding }>();
    for (const x of all) {
      const key = x.category ?? "other";
      const g = by.get(key);
      if (!g) by.set(key, { category: key, count: 1, worst: x.severity, sample: x });
      else { g.count++; if (SEVERITIES.indexOf(x.severity as any) < SEVERITIES.indexOf(g.worst as any)) { g.worst = x.severity; g.sample = x; } }
    }
    return [...by.values()].sort((a, b) => SEVERITIES.indexOf(a.worst as any) - SEVERITIES.indexOf(b.worst as any) || b.count - a.count);
  });
  const grouped = $derived(app.mode === "simple" && !filtered);
  let detailOpen = $state(false);
  $effect(() => { detailOpen = !!app.selected; });
</script>

<div class="flex flex-col gap-4">
  <div class="flex flex-wrap items-center gap-2">
    <label class="relative w-64">
      <Search size={14} class="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-gray-700" />
      <input class="input pl-8" bind:value={app.query} placeholder={t("findings.filter")} aria-label={t("findings.filter")} />
    </label>
    <Segmented items={sevItems} bind:value={sev} label={tr("Severity")} />
    {#if app.mode === "expert"}
      <Select items={hostItems} bind:value={app.host} label={tr("Host")} width="w-36" />
      <Select items={jobItems} bind:value={app.job} label={tr("Collector")} />
    {/if}
    {#if filtered}<button class="btn btn-ghost btn-sm" onclick={clear}>{tr("Clear filters")}</button>{/if}
    <span class="ml-auto text-copy-13 text-gray-900 tabular">{tr("{n} of {total}", { n: rows.length, total: all.length })}</span>
  </div>

  {#if grouped}
    <div class="card divide">
      {#each groups as g (g.category)}
        {@const p = plainFinding(g.sample)}
        <button class="row row-click w-full items-start gap-4 py-4 text-left" onclick={() => (app.query = g.category)}>
          <span class="{app.mode === 'simple' ? 'w-[112px]' : 'w-[76px]'} shrink-0 pt-px"><Pill severity={g.worst} /></span>
          <span class="min-w-0 flex-1">
            {#if hasGuide(g.sample)}
              <span class="block text-label-14">{tr(p.means)}</span>
              <span class="mt-0.5 block text-copy-13 text-gray-900">{g.count === 1 ? tr("1 item like this.") : tr("{n} items like this.", { n: g.count })} {tr(p.next)}</span>
            {:else}
              <span class="block text-label-14">{tr(groupLabel(g.category))}</span>
              <span class="mt-0.5 block text-copy-13 text-gray-900">{g.count === 1 ? tr("1 item like this.") : tr("{n} items like this.", { n: g.count })}</span>
            {/if}
          </span>
        </button>
      {/each}
    </div>
  {:else}
  <div class="card overflow-hidden">
    {#if !rows.length}
      <div class="empty">{all.length ? tr("Nothing matches these filters.") : app.error || t("findings.none")}</div>
    {:else}
      <div class="divide">
        {#each rows.slice(0, limit) as f, i (i)}
          <button class="row row-click w-full items-start text-left {app.selected === f ? 'bg-gray-100' : ''}" onclick={() => (app.selected = f)}>
            <span class="{app.mode === 'simple' ? 'w-[112px]' : 'w-[76px]'} shrink-0 pt-px"><Pill severity={f.severity} /></span>
            <span class="min-w-0 flex-1">
              {#if app.mode === "simple"}
                <span class="block truncate text-label-13">{brand(f.title)}</span>
                {#if hasGuide(f)}<span class="block truncate text-copy-13 text-gray-900">{tr(plainFinding(f).means)}</span>{/if}
              {:else}
                <span class="block truncate text-label-13">{f.title}</span>
                <span class="block truncate text-copy-13 text-gray-900">{f.detail}</span>
              {/if}
            </span>
            {#if f.ledger && f.ledger.state !== "open"}<span class="tag shrink-0">{f.ledger.state === "recurring" ? tr("Came back") : tr("Open for {age}", { age: f.ledger.age })}</span>{/if}
            {#if app.mode === "expert"}<span class="flex shrink-0 items-center gap-1.5 pt-px"><span class="tag">{f.job}</span><span class="tag">{f.host}</span></span>{/if}
          </button>
        {/each}
      </div>
      {#if rows.length > limit}
        <div class="border-t border-gray-300 p-3 text-center"><button class="btn btn-sm" onclick={() => (limit += 150)}>{tr("Show {n} more", { n: Math.min(150, rows.length - limit) })}</button></div>
      {/if}
    {/if}
  </div>
  {/if}
</div>

<Dialog.Root bind:open={detailOpen} onOpenChange={(o) => { if (!o) app.selected = null; }}>
  <Dialog.Portal>
    <Dialog.Overlay class="overlay" />
    <Dialog.Content class="popover fixed top-2 right-2 bottom-2 z-50 flex w-[440px] max-w-[calc(100vw-16px)] flex-col overflow-hidden p-0 anim-slide">
      {#if app.selected}
        {@const f = app.selected}
        <div class="flex items-start gap-3 border-b border-gray-300 p-5">
          <div class="min-w-0 flex-1">
            <Pill severity={f.severity} />
            <Dialog.Title class="selectable mt-2 text-heading-20">{brand(f.title)}</Dialog.Title>
          </div>
          <Dialog.Close class="btn btn-ghost w-8 justify-center px-0" aria-label={tr("Close")}><X size={16} /></Dialog.Close>
        </div>
        <div class="selectable flex-1 overflow-auto p-5">
          {#if app.mode === "simple"}
            {@const p = plainFinding(f)}
            <dl class="grid gap-3 text-copy-14">
              <div><dt class="text-label-13 text-gray-900">{tr("What this is")}</dt><dd class="mt-0.5">{tr(p.means)}</dd></div>
              <div><dt class="text-label-13 text-gray-900">{tr("Why it matters")}</dt><dd class="mt-0.5">{tr(p.why)}</dd></div>
              <div><dt class="text-label-13 text-gray-900">{tr("What you can do")}</dt><dd class="mt-0.5">{tr(p.next)}</dd></div>
            </dl>
            <details class="mt-5"><summary class="link cursor-default">{tr("Technical details")}</summary>
              <p class="mt-2 text-copy-13 text-gray-900">{f.detail}</p>
              <p class="mt-2 font-mono text-[12.5px] break-all">{f.where || ""}</p>
            </details>
          {:else}
          <Dialog.Description class="text-copy-14 text-gray-1000">{f.detail}</Dialog.Description>
          <dl class="mt-5 grid grid-cols-[96px_1fr] gap-x-4 gap-y-2.5 text-copy-13">
            <dt class="text-gray-900">{tr("Collector")}</dt><dd><span class="tag">{f.job}</span></dd>
            <dt class="text-gray-900">{tr("Host")}</dt><dd>{f.host === "win" ? "Windows" : f.host === "wsl" ? "WSL" : f.host}</dd>
            <dt class="text-gray-900">{tr("Category")}</dt><dd>{f.category ?? "—"}</dd>
            <dt class="text-gray-900">{tr("Location")}</dt><dd class="font-mono text-[12.5px] break-all">{f.where || "—"}</dd>
          </dl>
          {#if f.forensics?.length}
            <h3 class="mt-6 mb-2 text-label-13 text-gray-900">{tr("Forensics")}</h3>
            <pre class="rounded-lg bg-gray-100 p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-all">{f.forensics.join("\n")}</pre>
          {/if}
          {/if}
        </div>
      {/if}
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
