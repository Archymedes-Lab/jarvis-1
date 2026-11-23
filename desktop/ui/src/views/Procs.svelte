<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import Search from "@lucide/svelte/icons/search";
  import { api, type ProcsSnapshot } from "../lib/api";
  import { app, toast, openInBrowser } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";
  import { filterProcs, megabytes, procCounts, rowsFrom, type Baseline } from "../lib/procs";

  let snap = $state<ProcsSnapshot | null>(null);
  let baseline = $state<Baseline>(null);
  let err = $state("");
  let query = $state("");
  let onlyNew = $state(false);
  let limit = $state(80);
  let alive = true;
  let busy = false;
  let timer: ReturnType<typeof setInterval> | undefined;
  let lastBaseline = 0;

  async function load() {
    if (busy || !alive) return;
    busy = true;
    try {
      if (Date.now() - lastBaseline > 60000) { baseline = await api.procsBaseline().catch(() => baseline); lastBaseline = Date.now(); }
      snap = await api.procsSnapshot();
      err = "";
    } catch (e) { err = String((e as Error).message ?? e); }
    finally { busy = false; }
  }
  onMount(() => { load(); timer = setInterval(load, 6000); });
  onDestroy(() => { alive = false; clearInterval(timer); });
  $effect(() => { query; onlyNew; limit = 80; });

  const now = () => Date.now() / 1000;
  const win = $derived(rowsFrom(snap?.snaps?.win, baseline, "win", now()));
  const lin = $derived(rowsFrom(snap?.snaps?.lin, baseline, "lin", now()));
  const all = $derived([...win, ...lin.map((r) => ({ ...r, name: r.name }))]);
  const rows = $derived(filterProcs(all, query, onlyNew));
  const counts = $derived(procCounts(all));
  const baselineReady = $derived(!!(baseline && baseline.ok));
  const sources = $derived(snap?.status?.sources ?? {});
  const pill = { new: "pill-high", recent: "pill-info", unknown: "pill-low", known: "", approved: "pill-ok" } as Record<string, string>;
  const label = $derived({ new: tr("New name"), recent: tr("Seen today"), unknown: tr("Not judged"), known: tr("Known"), approved: tr("Approved") } as Record<string, string>);
  const started = (ms: number) => (ms ? new Date(ms).toLocaleString(app.lang, { dateStyle: "short", timeStyle: "short" }) : "—");
  const full = () => openInBrowser("procs");
</script>

<div class="flex flex-col gap-6">
  <div class="flex items-start gap-4">
    <div class="max-w-[760px]">
      <h2 class="text-heading-24">{tr("Running programs")}</h2>
      <p class="mt-1 text-copy-14 text-gray-900">{tr("\"New\" means never seen on this computer, not harmful.")}</p>
    </div>
    <button class="btn btn-sm ml-auto shrink-0" onclick={full}>{tr("Open full view")}</button>
  </div>

  {#if err && !snap}
    <div class="empty">{err}</div>
  {:else if !snap}
    <div class="empty">{tr("Reading ARGUS-INSTINCT…")}</div>
  {:else}
    {#if !baselineReady}
      <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900"><span class="dot dot-warn"></span>{tr("ARGUS-INSTINCT has not learned what is normal here yet, so nothing can be marked new.")}</div>
    {/if}
    {#each Object.entries(sources) as [h, s]}
      {#if (s as any).state && !["live", "ok", "fresh"].includes((s as any).state) && (s as any).state !== "absent"}
        <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900"><span class="dot dot-warn"></span>{tr("The {host} process feed is {state}.", { host: h === "win" ? "Windows" : h === "lin" ? "WSL" : h, state: (s as any).state })}</div>
      {/if}
    {/each}

    <section class="grid grid-cols-3 gap-3 max-sm:grid-cols-1">
      <div class="card p-5"><div class="text-label-13 text-gray-900">{tr("Programs running")}</div><div class="mt-1 text-display text-[30px] leading-[34px] tabular">{counts.total}</div></div>
      <div class="card p-5"><div class="text-label-13 text-gray-900">{tr("New or seen only today")}</div><div class="mt-1 text-display text-[30px] leading-[34px] tabular {counts.fresh ? 'text-amber-900' : ''}">{baselineReady ? counts.fresh : "—"}</div></div>
      <div class="card p-5"><div class="text-label-13 text-gray-900">{tr("Refreshed every 6 seconds")}</div><div class="mt-1 flex items-center gap-2 text-copy-13 text-gray-900"><span class="dot dot-run"></span>{tr("Live")}</div></div>
    </section>

    <section class="flex flex-col gap-3">
      <div class="flex flex-wrap items-center gap-3">
        <label class="relative w-72">
          <Search size={14} class="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-gray-700" />
          <input class="input pl-8" bind:value={query} placeholder={tr("Search by name or number")} aria-label={tr("Search by name or number")} />
        </label>
        <label class="flex items-center gap-2 text-copy-13"><input type="checkbox" bind:checked={onlyNew} />{tr("Only new or seen today")}</label>
        <span class="ml-auto text-copy-13 text-gray-900 tabular">{tr("{n} of {total}", { n: rows.length, total: all.length })}</span>
      </div>
      <div class="card overflow-hidden">
        {#if !rows.length}
          <div class="empty">{tr("Nothing matches these filters.")}</div>
        {:else}
          <div class="divide">
            {#each rows.slice(0, limit) as r (r.key)}
              <div class="row">
                <span class="w-[92px] shrink-0">{#if baselineReady}<span class="pill {pill[r.cls]}">{label[r.cls]}</span>{/if}</span>
                <span class="min-w-0 flex-1">
                  <span class="block truncate text-label-13">{r.name || "—"}</span>
                  <span class="block truncate text-copy-13 text-gray-900">{tr("Started {when}", { when: started(r.created) })}</span>
                </span>
                {#if app.mode === "expert"}<span class="tag shrink-0">pid {r.pid}</span><span class="tag shrink-0 max-md:hidden">ppid {r.ppid}</span>{/if}
                <span class="w-20 shrink-0 text-right text-copy-13 text-gray-900 tabular">{megabytes(r.rss)}</span>
              </div>
            {/each}
          </div>
          {#if rows.length > limit}
            <div class="border-t border-gray-300 p-3 text-center"><button class="btn btn-sm" onclick={() => (limit += 80)}>{tr("Show {n} more", { n: Math.min(80, rows.length - limit) })}</button></div>
          {/if}
        {/if}
      </div>
    </section>
  {/if}
</div>
