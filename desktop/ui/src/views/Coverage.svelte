<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import Search from "@lucide/svelte/icons/search";
  import { api, type Coverage } from "../lib/api";
  import { app, toast, openInBrowser } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";
  import Pill from "../components/Pill.svelte";

  const data = $derived(app.coverage as Coverage | null);
  let err = $state("");
  let level = $state("");
  let stage = $state("");
  let query = $state("");
  let limit = $state(60);

  // Fresh on open, then every 30 s while open; the sidebar shares the same map.
  async function load() {
    try { app.coverage = await api.coverage(); err = ""; }
    catch (e) { err = String((e as Error).message ?? e); }
  }
  let timer: ReturnType<typeof setInterval> | undefined;
  onMount(() => { load(); timer = setInterval(load, 30000); });
  onDestroy(() => clearInterval(timer));
  $effect(() => { level; query; stage; limit = 60; });

  const LEVELS = ["validated", "claimed", "blind", "regressed"] as const;
  const label = $derived((app.mode === "simple"
    ? { validated: tr("Working"), claimed: tr("Should work"), blind: tr("Cannot see yet"), regressed: tr("Stopped working") }
    : { validated: tr("Proven"), claimed: tr("Expected"), blind: tr("Blind spot"), regressed: tr("Got worse") }) as Record<string, string>);
  const tone: Record<string, string> = { validated: "var(--green-700)", claimed: "var(--blue-700)", blind: "var(--amber-700)", regressed: "var(--red-700)" };
  const pill: Record<string, string> = { validated: "pill-ok", claimed: "pill-info", blind: "pill-high", regressed: "pill-critical" };
  const pretty = (id: string) => id.replace(/-/g, " ").replace(/^./, (c) => c.toUpperCase());
  // Simple: what the attacker is trying to do at each step, in everyday words. Expert keeps the ATT&CK names.
  const plainStage = $derived<Record<string, string>>({
    "reconnaissance": tr("Looking for a target"), "resource-development": tr("Getting tools ready"),
    "initial-access": tr("Getting in"), "execution": tr("Running their program"),
    "persistence": tr("Staying after a restart"), "privilege-escalation": tr("Getting more power"),
    "defense-evasion": tr("Hiding from protection"), "credential-access": tr("Stealing passwords"),
    "discovery": tr("Looking around"), "lateral-movement": tr("Moving to other computers"),
    "collection": tr("Gathering your files"), "command-and-control": tr("Taking orders from far away"),
    "exfiltration": tr("Sending your files out"), "impact": tr("Breaking or locking things"),
  });
  const stageName = (id: string) => (app.mode === "simple" && plainStage[id]) || pretty(id);

  // What needs a look comes first: got worse, then blind spots, then expected, then proven.
  const RANK: Record<string, number> = { regressed: 0, blind: 1, claimed: 2, validated: 3 };
  const rows = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return (data?.techniques ?? [])
      .filter((t) => (!level || t.level === level) && (!stage || (t.tactics ?? []).includes(stage))
        && (!q || `${t.tid} ${t.name} ${(t.tactics ?? []).join(" ")}`.toLowerCase().includes(q)))
      .sort((a, b) => (RANK[a.level] ?? 9) - (RANK[b.level] ?? 9) || a.name.localeCompare(b.name));
  });
  const gaps = $derived((data?.intel_gaps?.items ?? []).filter((g) => g.kind === "coverage gap"));
  let gapLimit = $state(12);
  const share = (n: number) => (data && data.totals.total ? (n / data.totals.total) * 100 : 0);
  const watched = $derived(Math.round((data?.uptime?.pct24 ?? 0) * 100));
  const full = () => openInBrowser("coverage");
</script>

<div class="flex flex-col gap-6">
  <div class="flex items-start gap-4">
    <h2 class="text-heading-24">{tr("What Argus can see")}</h2>
    <button class="btn btn-sm ml-auto shrink-0" onclick={full}>{tr("Open full map")}</button>
  </div>

  {#if err && !data}
    <div class="empty">{err}</div>
  {:else if !data}
    <div class="empty">{tr("Reading ARGUS-INSTINCT…")}</div>
  {:else}
    <section class="card p-6">
      <div class="flex flex-wrap items-baseline gap-x-8 gap-y-1">
        <h3 class="text-heading-20 tabular">{app.mode === "simple" ? tr("{n} attacker tricks", { n: data.totals.total }) : tr("{n} techniques", { n: data.totals.total })}</h3>
        <p class="ml-auto text-copy-13 text-gray-900">{tr("Watched {n}% of the last 24 hours", { n: watched })}</p>
      </div>
      <div class="mt-5 flex h-1.5 overflow-hidden bg-gray-200" role="img"
           aria-label={LEVELS.map((l) => `${label[l]} ${data?.totals[l] ?? 0}`).join(", ")}>
        {#each LEVELS as l}<i style:width="{share(data.totals[l])}%" style:background={tone[l]}></i>{/each}
      </div>
      <div class="mt-4 grid grid-cols-4 gap-3 max-md:grid-cols-2">
        {#each LEVELS as l}
          <button class="rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-gray-100 {level === l ? 'bg-gray-100 ring-2 ring-blue-700' : ''}"
                  onclick={() => (level = level === l ? "" : l)} aria-pressed={level === l}>
            <span class="flex items-center gap-2 text-label-13 text-gray-900"><span class="size-2 rounded-full" style:background={tone[l]}></span>{label[l]}</span>
            <span class="mt-0.5 block text-heading-24 tabular">{data.totals[l]}</span>
          </button>
        {/each}
      </div>
    </section>

    <section class="card">
      <div class="card-head">{app.mode === "simple" ? tr("Steps of an attack") : tr("By stage of an attack")}</div>
      <div class="grid grid-cols-2 gap-x-8 gap-y-3 px-5 pb-5 max-md:grid-cols-1">
        {#each Object.entries(data.tactics) as [id, c]}
          {@const total = Math.max(1, c.total ?? 0)}
          <button class="-mx-2 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-gray-100 {stage === id ? 'bg-gray-100 ring-2 ring-blue-700' : ''}"
                  onclick={() => (stage = stage === id ? "" : id)} aria-pressed={stage === id}>
            <div class="mb-1 flex justify-between text-copy-13"><span>{stageName(id)}</span><span class="tabular text-gray-900">{c.total}</span></div>
            <div class="flex h-1 overflow-hidden bg-gray-200" role="img" aria-label="{stageName(id)}: {LEVELS.map((l) => `${label[l]} ${c[l] ?? 0}`).join(', ')}">
              {#each LEVELS as l}<i style:width="{((c[l] ?? 0) / total) * 100}%" style:background={tone[l]}></i>{/each}
            </div>
          </button>
        {/each}
      </div>
    </section>

    {#if gaps.length}
      <section class="card">
        <div class="card-head">{app.mode === "simple" ? tr("Tricks ARGUS-INSTINCT cannot spot yet") : tr("Detection gaps")} <span class="tabular text-gray-900">{gaps.length}</span></div>
        <p class="px-5 text-copy-13 text-gray-900">{app.mode === "simple" ? tr("Attackers have newer tricks that ARGUS-INSTINCT does not check for yet. This is about ARGUS-INSTINCT, not about your computer.") : tr("Techniques current threat intelligence describes that ARGUS-INSTINCT does not check yet. These are about the tool, not about this computer.")}</p>
        <div class="divide mt-2">
          {#each gaps.slice(0, gapLimit) as g (g.tid)}
            <div class="row items-start">
              <span class="{app.mode === 'simple' ? 'w-[112px]' : 'w-[76px]'} shrink-0 pt-px"><Pill severity={g.priority} /></span>
              <span class="min-w-0 flex-1"><span class="block truncate text-label-13">{g.name || g.tid}</span>
                <span class="block truncate text-copy-13 text-gray-900">{g.detail}</span></span>
              {#if app.mode === "expert"}<span class="tag shrink-0">{g.tid}</span>{/if}
            </div>
          {/each}
        </div>
        {#if gaps.length > gapLimit}
          <div class="border-t border-gray-300 p-3 text-center"><button class="btn btn-sm" onclick={() => (gapLimit += 60)}>{tr("Show {n} more", { n: Math.min(60, gaps.length - gapLimit) })}</button></div>
        {/if}
      </section>
    {/if}

    <section class="flex flex-col gap-3">
      <div class="flex items-center gap-3">
        <label class="relative w-72">
          <Search size={14} class="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-gray-700" />
          <input class="input pl-8" bind:value={query} placeholder={app.mode === "simple" ? tr("Search") : tr("Search techniques")} aria-label={app.mode === "simple" ? tr("Search") : tr("Search techniques")} />
        </label>
        {#if level || stage}<button class="btn btn-ghost btn-sm" onclick={() => { level = ""; stage = ""; }}>{tr("Clear filters")}</button>{/if}
        <span class="ml-auto text-copy-13 text-gray-900 tabular">{tr("{n} of {total}", { n: rows.length, total: data.techniques.length })}</span>
      </div>
      <div class="card overflow-hidden">
        {#if !rows.length}
          <div class="empty">{tr("Nothing matches these filters.")}</div>
        {:else}
          <div class="divide">
            {#each rows.slice(0, limit) as t (t.tid)}
              <div class="row items-start">
                <span class="{app.mode === 'simple' ? 'w-[128px]' : 'w-[92px]'} shrink-0 pt-px"><span class="pill {pill[t.level] ?? 'pill-low'}">{label[t.level] ?? t.level}</span></span>
                <span class="min-w-0 flex-1">
                  <span class="block truncate text-label-13">{t.name}</span>
                  <span class="block truncate text-copy-13 text-gray-900">{(t.tactics ?? []).map(stageName).join(", ")}</span>
                </span>
                {#if app.mode === "expert"}<span class="tag shrink-0">{t.tid}</span>{/if}
              </div>
            {/each}
          </div>
          {#if rows.length > limit}
            <div class="border-t border-gray-300 p-3 text-center"><button class="btn btn-sm" onclick={() => (limit += 60)}>{tr("Show {n} more", { n: Math.min(60, rows.length - limit) })}</button></div>
          {/if}
        {/if}
      </div>
    </section>
  {/if}
</div>
