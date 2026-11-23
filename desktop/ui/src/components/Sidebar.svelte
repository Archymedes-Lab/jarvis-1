<script lang="ts">
  import Download from "@lucide/svelte/icons/download";
  import { api } from "../lib/api";
  import { app, go, type View } from "../lib/store.svelte";
  import { EXPERT_ONLY, NAV, type NavGroup } from "../lib/nav";
  import { t, type Key } from "../lib/words";
  import { tr } from "../lib/i18n";
  import { collectorSummary, groupQuestions, problemCounts } from "../lib/model";
  import { LEVELS, summarize } from "../lib/coverage";

  const counts = $derived(app.data ? problemCounts(app.data.findings ?? []) : null);
  const coll = $derived(app.data ? collectorSummary(app.data.jobs ?? []) : null);
  // Same count as the home page: questions, fix proposals and grouped cases.
  const review = $derived(app.data ? groupQuestions(app.data.questions ?? []).length + (app.data.fix ?? []).length + app.casesWaiting : 0);
  const cov = $derived(summarize(app.coverage));
  const simple = $derived(app.mode === "simple");
  const LEVEL_NAME = $derived((simple
    ? { validated: tr("Working"), claimed: tr("Should work"), blind: tr("Cannot see yet"), regressed: tr("Stopped working") }
    : { validated: tr("Proven"), claimed: tr("Expected"), blind: tr("Blind spot"), regressed: tr("Got worse") }) as Record<string, string>);
  const TONE: Record<string, string> = { validated: "var(--green-700)", claimed: "var(--blue-700)", blind: "var(--amber-700)", regressed: "var(--red-700)" };

  function badge(v: View): { n: number; tone: string } | null {
    if (v === "findings" && counts?.critical) return { n: counts.critical, tone: "text-amber-900" };
    if (v === "collectors" && coll && coll.stale + coll.error) return { n: coll.stale + coll.error, tone: "text-amber-900" };
    if (v === "review" && review) return { n: review, tone: "text-blue-900" };
    return null;
  }
  const shown = (g: NavGroup) => NAV.filter((n) => n.group === g && (app.mode === "expert" || !EXPERT_ONLY.includes(n.view)));
  const live = $derived(app.status.phase === "live");
  const paused = $derived(live && (app.data?.paused_until ?? 0) * 1000 > Date.now());
</script>

{#snippet item(n: (typeof NAV)[number])}
  {@const b = badge(n.view)}
  {@const Icon = n.icon}
  <button class="nav-item" data-view={n.view} aria-current={app.view === n.view ? "page" : undefined} onclick={() => go(n.view)}>
    <Icon size={simple ? 18 : 15} strokeWidth={simple ? 1.9 : 2} />
    <span class="truncate">{t(`nav.${n.view}` as Key)}</span>
    {#if b}<span class="nav-count {b.tone}">{b.n}</span>{/if}
  </button>
{/snippet}

<!-- The sidebar shares the page canvas. Simple: wide, large rows. Expert: narrow, dense, with section labels. -->
<aside class="flex shrink-0 flex-col overflow-y-auto {simple ? 'w-[252px]' : 'w-[224px] border-r border-gray-300'}">
  <div class="flex shrink-0 items-center gap-2.5 {simple ? 'h-16 px-[22px]' : 'h-13 px-[18px]'}">
    <span class="brand-mark" aria-hidden="true">
      <!-- The watching eye: Argus. -->
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" /><circle cx="12" cy="12" r="2.6" fill="currentColor" stroke="none" />
      </svg>
    </span>
    <span class="font-bold tracking-[0.05em] {simple ? 'text-[13.5px]' : 'text-label-13'}">ARGUS-INSTINCT</span>
  </div>

  <nav class="flex flex-col gap-0.5 pb-1" aria-label={tr("Sections")}>
    {#each shown("main") as n (n.view)}{@render item(n)}{/each}
  </nav>

  <!-- Coverage, always in view: what the daemon reports, expected never added to proven. -->
  <div class="side-section">
    <button class="side-panel group block w-[calc(100%-16px)] cursor-default" data-view="coverage" onclick={() => go("coverage")}
            aria-current={app.view === "coverage" ? "page" : undefined}>
      <span class="block pb-2 text-eyebrow {app.view === 'coverage' ? 'text-gray-1000' : 'text-gray-700 group-hover:text-gray-1000'}">{t("nav.coverage")}</span>
      {#if cov}
        <span class="flex h-1.5 gap-px overflow-hidden rounded-full bg-gray-300" role="img"
              aria-label={LEVELS.map((l) => `${LEVEL_NAME[l]} ${cov.counts[l]}`).join(", ")}>
          {#each LEVELS as l}<i style:width="{cov.shares[l] * 100}%" style:background={TONE[l]}></i>{/each}
        </span>
        <span class="mt-2.5 grid grid-cols-[1fr_auto] gap-y-1 text-label-12">
          {#each LEVELS as l}
            {#if l !== "regressed" || cov.counts.regressed}
              <span class="flex items-center gap-2 text-gray-900"><i class="size-1.5 rounded-full" style:background={TONE[l]}></i>{LEVEL_NAME[l]}</span>
              <span class="tabular text-right {l === 'regressed' ? 'text-red-900' : 'text-gray-1000'}">{cov.counts[l]}</span>
            {/if}
          {/each}
          {#if cov.watched !== null}
            <span class="col-span-2 mt-1 font-normal text-gray-700">{tr("Watched {n}% of the last 24 hours", { n: cov.watched })}</span>
          {/if}
        </span>
      {:else}
        <span class="block text-copy-13 text-gray-700">{tr("Reading ARGUS-INSTINCT…")}</span>
      {/if}
    </button>
  </div>

  <nav class="side-section flex flex-col gap-0.5" aria-label={tr("Explore")}>
    <p class="side-label">{tr("Explore")}</p>
    {#each shown("explore").filter((n) => n.view !== "coverage") as n (n.view)}{@render item(n)}{/each}
  </nav>

  <div class="mt-auto pt-3">
    {#if app.update?.newer}
      <div class="mx-2 mb-2 flex items-center gap-2 rounded-xl bg-blue-100 px-3 py-2" role="status">
        <span class="min-w-0 flex-1 text-label-12 text-blue-900">{tr("Version {v} is ready to download.", { v: app.update.latest ?? "" })}</span>
        <button class="btn btn-sm btn-accent shrink-0" onclick={() => api.openDownloadPage().catch(() => {})} aria-label={tr("Get the update")}>
          <Download size={13} />
        </button>
      </div>
    {/if}
    <nav class="flex flex-col gap-0.5 pb-2" aria-label={tr("Account")}>
      {#each shown("bottom") as n (n.view)}{@render item(n)}{/each}
    </nav>
    <div class="mx-2 mb-3 flex items-center gap-2.5 rounded-xl bg-gray-200/70 px-3 py-2.5 text-label-12 text-gray-900">
      <span class="dot {live ? (paused ? 'dot-warn' : 'dot-ok') : app.status.phase === 'degraded' ? 'dot-warn' : app.status.phase === 'starting' ? 'dot-run' : 'dot-bad'}"></span>
      <span class="truncate" title={app.status.detail || tr(app.status.message)}>{live ? (paused ? tr("On a break") : tr("Watching"))
        : app.status.blind?.length ? (app.status.blind.length === 1 ? tr("Watching · 1 check limited") : tr("Watching · {n} checks limited", { n: app.status.blind.length }))
        : tr(app.status.message)}</span>
    </div>
  </div>
</aside>
