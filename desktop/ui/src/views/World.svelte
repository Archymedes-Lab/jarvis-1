<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import Search from "@lucide/svelte/icons/search";
  import TrendingUp from "@lucide/svelte/icons/trending-up";
  import TrendingDown from "@lucide/svelte/icons/trending-down";
  import Minus from "@lucide/svelte/icons/minus";
  import { api, type World, type WorldZone } from "../lib/api";
  import { app, toast, openInBrowser } from "../lib/store.svelte";
  import { agoT, tr } from "../lib/i18n";

  let data = $state<World | null>(null);
  let err = $state("");
  let busy = $state(false);
  let alive = true;
  let loading = false;
  let query = $state("");
  let zone = $state<WorldZone | null>(null);
  let limit = $state(40);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load() {
    if (loading || !alive) return;
    loading = true;
    try { data = await api.world(); err = ""; }   // shaped in lib/shape.ts: never missing a list
    catch (e) { err = String((e as Error).message ?? e); }
    finally { loading = false; }
  }
  // Ask ARGUS-INSTINCT to fetch the news reports again now, then show them as soon as they arrive.
  async function refresh() {
    busy = true;
    try {
      await api.runCollector("world");
      toast(tr("Fetching the latest reports…"), "ok");
      for (const wait of [5000, 10000, 20000]) { await new Promise((r) => setTimeout(r, wait)); if (!alive) return; await load(); }
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  onMount(() => { load(); timer = setInterval(load, 30000); });
  onDestroy(() => { alive = false; clearInterval(timer); });
  $effect(() => { query; zone; limit = 40; });

  // Great-circle distance, to say which reports fall inside a zone.
  function km(aLat: number, aLon: number, bLat: number, bLon: number): number {
    const r = Math.PI / 180, dLat = (bLat - aLat) * r, dLon = (bLon - aLon) * r;
    const h = Math.sin(dLat / 2) ** 2 + Math.cos(aLat * r) * Math.cos(bLat * r) * Math.sin(dLon / 2) ** 2;
    return 12742 * Math.asin(Math.min(1, Math.sqrt(h)));
  }
  const items = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return (data?.items ?? [])
      .filter((i) => (!zone || (i.lat != null && i.lon != null && km(zone.lat, zone.lon, i.lat, i.lon) <= (zone.radius_km ?? 150)))
        && (!q || `${i.title} ${i.place ?? ""} ${i.country ?? ""} ${i.source}`.toLowerCase().includes(q)))
      .sort((a, b) => b.ts - a.ts);
  });
  const zones = $derived([...(data?.zones ?? [])].sort((a, b) => b.reports - a.reports));
  const okSources = $derived((data?.sources ?? []).filter((s) => !s.error && s.ok).length);
  const full = () => openInBrowser("world");
</script>

<div class="flex flex-col gap-6">
  <div class="flex items-start gap-4">
    <div class="max-w-[760px]">
      <h2 class="text-heading-24">{tr("World events")}</h2>
      <p class="mt-1 text-copy-14 text-gray-900">{tr("Public news reports. A zone is a cluster of reports, not proof.")}</p>
    </div>
    <button class="btn btn-sm ml-auto shrink-0" onclick={full}>{tr("Open full globe")}</button>
  </div>

  {#if err && !data}
    <div class="empty">{err}</div>
  {:else if !data}
    <div class="empty">{tr("Reading ARGUS-INSTINCT…")}</div>
  {:else}
    {#if err}
      <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900"><span class="dot dot-warn"></span>{tr("Could not refresh. Showing what ARGUS-INSTINCT received last.")}</div>
    {/if}
    {#if data.stale}
      <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900"><span class="dot dot-warn"></span><span class="min-w-0 flex-1">{app.mode === "simple" ? tr("The news is out of date. It was last updated {when}.", { when: agoT(data.generated_at) }) : tr("The news feed is out of date.")}</span>
        <button class="btn btn-sm shrink-0" disabled={busy} onclick={refresh}>{busy ? tr("Updating…") : tr("Update now")}</button></div>
    {:else if !data.items.length}
      <div class="flex items-center gap-3 rounded-lg bg-gray-100 px-4 py-2.5 text-copy-13 text-gray-900"><span class="min-w-0 flex-1">{tr("No reports have come in lately. That can be normal.")}</span>
        <button class="btn btn-sm shrink-0" disabled={busy} onclick={refresh}>{busy ? tr("Updating…") : tr("Update now")}</button></div>
    {/if}

    <section class="grid grid-cols-4 gap-3 max-md:grid-cols-2">
      {#each [[tr("Reports"), data.counts.reports], [tr("Placed on the map"), data.counts.mapped], [tr("Active zones"), zones.length], [tr("Sources working"), `${okSources} / ${data.sources.length}`]] as [k, n]}
        <div class="card p-5"><div class="text-label-13 text-gray-900">{k}</div><div class="mt-1 text-display text-[30px] leading-[34px] tabular">{n}</div></div>
      {/each}
    </section>
    <p class="-mt-3 text-copy-13 text-gray-900">{tr("Updated {when}", { when: agoT(data.generated_at) })}</p>

    <section class="card">
      <div class="card-head">{tr("Where reports cluster")}{#if zone}<button class="btn btn-ghost btn-sm ml-auto" onclick={() => (zone = null)}>{tr("Show all places")}</button>{/if}</div>
      {#if !zones.length}
        <div class="empty">{tr("No clusters right now.")}</div>
      {:else}
        <div class="divide">
          {#each zones as z (z.id)}
            {@const up = z.last_24h > z.prior_24h}
            {@const down = z.last_24h < z.prior_24h}
            <button class="row row-click w-full text-left {zone?.id === z.id ? 'bg-gray-100' : ''}" onclick={() => (zone = zone?.id === z.id ? null : z)}>
              <span class="min-w-0 flex-1">
                <span class="block truncate text-label-13">{z.name}</span>
                <span class="block truncate text-copy-13 text-gray-900">{tr("{n} reports from {s} sources", { n: z.reports, s: z.sources })}</span>
              </span>
              <span class="flex shrink-0 items-center gap-1.5 text-copy-13 {up ? 'text-amber-900' : 'text-gray-900'}">
                {#if up}<TrendingUp size={14} />{:else if down}<TrendingDown size={14} />{:else}<Minus size={14} />{/if}
                {tr("{a} in 24 h (before: {b})", { a: z.last_24h, b: z.prior_24h })}
              </span>
            </button>
          {/each}
        </div>
      {/if}
    </section>

    <section class="flex flex-col gap-3">
      <div class="flex items-center gap-3">
        <h3 class="text-heading-16">{zone ? zone.name : tr("Latest reports")}</h3>
        <label class="relative ml-auto w-72">
          <Search size={14} class="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-gray-700" />
          <input class="input pl-8" bind:value={query} placeholder={tr("Search reports")} aria-label={tr("Search reports")} />
        </label>
      </div>
      <div class="card overflow-hidden">
        {#if !items.length}
          <div class="empty">{tr("No reports match.")}</div>
        {:else}
          <div class="divide">
            {#each items.slice(0, limit) as i (i.id ?? i.ts + i.title)}
              <div class="row items-start">
                <span class="min-w-0 flex-1">
                  <span class="selectable block text-label-13">{i.title}</span>
                  <span class="block truncate text-copy-13 text-gray-900">{[i.place, i.country].filter(Boolean).join(", ") || tr("Place unknown")}</span>
                </span>
                <span class="shrink-0 text-right text-copy-13 text-gray-900">{agoT(i.ts)}{#if app.mode === "expert"}<br /><span class="tag">{i.source}</span>{/if}</span>
              </div>
            {/each}
          </div>
          {#if items.length > limit}
            <div class="border-t border-gray-300 p-3 text-center"><button class="btn btn-sm" onclick={() => (limit += 40)}>{tr("Show {n} more", { n: Math.min(40, items.length - limit) })}</button></div>
          {/if}
        {/if}
      </div>
    </section>

    <details class="card px-5 py-3">
      <summary class="cursor-default text-label-13">{tr("Sources")}</summary>
      <div class="divide mt-3">
        {#each data.sources as s (s.key)}
          <div class="row"><span class="dot {s.error || !s.ok ? 'dot-warn' : 'dot-ok'}"></span><span class="min-w-0 flex-1 truncate text-label-13">{s.name}</span><span class="text-copy-13 text-gray-900">{tr("{n} reports", { n: s.reports })}</span></div>
        {/each}
      </div>
      {#if app.mode === "expert" && data.rules}<p class="mt-3 text-copy-13 text-gray-900">{data.rules.note}</p>{/if}
    </details>
  {/if}
</div>
