<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import MapPin from "@lucide/svelte/icons/map-pin";
  import { api, type Geo } from "../lib/api";
  import { app, toast, openInBrowser } from "../lib/store.svelte";
  import { agoT, tr } from "../lib/i18n";

  let data = $state<Geo | null>(null);
  let err = $state("");
  let busy = $state(false);
  let asked = $state(false);
  let alive = true;
  let loading = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load() {
    if (loading || !alive) return;
    loading = true;
    try { data = await api.geo(); err = ""; }
    catch (e) { err = String((e as Error).message ?? e); }
    finally { loading = false; }
  }
  // Ask ARGUS-INSTINCT to take a new location reading now, then show it as soon as it is ready.
  async function refresh() {
    busy = true;
    try {
      await api.runCollector("geo");
      asked = true;
      toast(tr("Updating the location…"), "ok");
      for (const wait of [3000, 6000, 12000]) { await new Promise((r) => setTimeout(r, wait)); if (!alive) return; await load(); }
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  onMount(() => { load(); timer = setInterval(load, 15000); });
  onDestroy(() => { alive = false; clearInterval(timer); });

  const loc = $derived(data?.location);
  const located = $derived(!!loc && loc.status === "ok" && loc.lat != null && loc.lon != null);
  const fixAge = $derived(loc?.ts ? Math.max(0, Date.now() / 1000 - loc.ts) : null);
  const oldFix = $derived(located && fixAge !== null && fixAge > 900);
  const pct = $derived(Math.round((data?.confidence?.score ?? 0) * 100));
  const trustLabel = (t: string) => ({ trusted: tr("Trusted"), degraded: tr("Needs a look"), untrusted: tr("Not trusted") } as Record<string, string>)[t] ?? t;
  const zoneName = (z?: string) => (!z || z === "outside" ? tr("Outside your trusted zones") : z);
  const full = () => openInBrowser("geo");
</script>

<div class="mx-auto flex max-w-[820px] flex-col gap-6">
  <div class="flex items-start gap-4">
    <div>
      <h2 class="text-heading-24">{tr("Where this computer is")}</h2>
      <p class="mt-1 text-copy-14 text-gray-900">{tr("Approximate location. No outside map is loaded here.")}</p>
    </div>
    <button class="btn btn-sm ml-auto shrink-0" onclick={full}>{tr("Open full map")}</button>
  </div>

  {#if err && data}
    <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900"><span class="dot dot-warn"></span>{tr("Could not refresh. Showing what ARGUS-INSTINCT received last.")}</div>
  {/if}

  {#if err && !data}
    <div class="empty">{err}</div>
  {:else if !data}
    <div class="empty">{tr("Reading ARGUS-INSTINCT…")}</div>
  {:else}
    {#if oldFix}
      <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900"><span class="dot dot-warn"></span><span class="min-w-0 flex-1">{tr("The last location reading was {when}. ARGUS-INSTINCT may not have updated it recently.", { when: agoT(loc!.ts) })}</span>
        <button class="btn btn-sm shrink-0" disabled={busy} onclick={refresh}>{busy ? tr("Updating…") : tr("Update now")}</button></div>
    {/if}
    <section class="card flex items-start gap-5 p-6">
      <span class="grid size-12 shrink-0 place-items-center rounded-2xl {located ? 'bg-blue-100 text-blue-900' : 'bg-gray-100 text-gray-900'}"><MapPin size={22} /></span>
      <div class="min-w-0 flex-1">
        {#if located}
          {#if app.mode === "simple"}
            <p class="text-heading-20">{zoneName(loc!.zone)}</p>
            <p class="mt-1 text-copy-14 tabular text-gray-900">{tr("Map position: {lat}, {lon}", { lat: loc!.lat!.toFixed(4), lon: loc!.lon!.toFixed(4) })}</p>
          {:else}
            <p class="text-heading-20 tabular">{loc!.lat!.toFixed(4)}, {loc!.lon!.toFixed(4)}</p>
            <p class="mt-1 text-copy-14 text-gray-900">{zoneName(loc!.zone)}</p>
          {/if}
          <dl class="mt-4 grid grid-cols-[130px_1fr] gap-x-4 gap-y-2 text-copy-13">
            <dt class="text-gray-900">{tr("Accuracy")}</dt><dd>{tr("within about {n} m", { n: loc!.accuracy_m ?? "?" })}</dd>
            {#if app.mode === "expert"}<dt class="text-gray-900">{tr("Source")}</dt><dd><span class="tag">{loc!.source}</span></dd>{/if}
            <dt class="text-gray-900">{app.mode === "simple" ? tr("Last update") : tr("Last fix")}</dt><dd>{agoT(loc!.ts)}</dd>
          </dl>
        {:else}
          <p class="text-heading-20">{tr("Location unavailable")}</p>
          <p class="mt-1 text-copy-14 text-gray-900">{tr("This computer has not reported where it is. Location services may be off.")}</p>
          <button class="btn btn-sm mt-3" disabled={busy} onclick={refresh}>{busy ? tr("Updating…") : tr("Try again")}</button>
          {#if asked && !busy}<p class="mt-2 text-copy-13 text-gray-900">{tr("Still no location. Check that Windows location services are on for this computer.")}</p>{/if}
        {/if}
      </div>
    </section>

    {#if data.confidence}
      <section class="card p-5">
        <div class="flex items-center justify-between text-label-13"><span>{tr("How sure ARGUS-INSTINCT is")}</span><span class="tabular">{pct}%</span></div>
        <div class="meter mt-2"><i style:width="{pct}%" style:background={pct >= 70 ? "var(--green-700)" : pct >= 40 ? "var(--amber-700)" : "var(--gray-600)"}></i></div>
        {#if app.mode === "expert"}
          <ul class="mt-3 text-copy-13 text-gray-900">{#each data.confidence.signals ?? [] as s}<li>{s.name} · {s.weight}</li>{/each}</ul>
        {/if}
      </section>
    {/if}

    <section class="card">
      <div class="card-head">{tr("Devices")}</div>
      {#if !data.devices.length}
        <div class="empty">{tr("None")}</div>
      {:else}
        <div class="divide">
          {#each data.devices as d}
            <div class="row"><span class="min-w-0 flex-1"><span class="block truncate text-label-13">{d.name}</span><span class="block truncate text-copy-13 text-gray-900">{d.located ? zoneName(d.zone) : tr("Not located")}</span></span>
              <span class="pill {d.trust === 'trusted' ? 'pill-ok' : 'pill-high'}">{trustLabel(d.trust)}</span></div>
          {/each}
        </div>
      {/if}
    </section>

    <section class="card">
      <div class="card-head">{tr("Trusted zones")}</div>
      {#if !data.zones.length}
        <div class="empty">{tr("None set. Add zones such as home or the office in the full map.")}</div>
      {:else}
        <div class="divide">{#each data.zones as z}<div class="row"><span class="text-label-13">{z.name}</span></div>{/each}</div>
      {/if}
    </section>

    <section class="card">
      <div class="card-head">{tr("Warnings")}</div>
      {#if !data.anomalies.length}
        <div class="empty">{tr("Nothing unusual about where this computer has been.")}</div>
      {:else}
        <div class="divide">{#each data.anomalies as a}<div class="row selectable text-copy-13">{typeof a === "string" ? a : (a.title ?? a.message ?? JSON.stringify(a))}</div>{/each}</div>
      {/if}
    </section>
  {/if}
</div>
