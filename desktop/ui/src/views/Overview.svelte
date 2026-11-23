<script lang="ts">
  import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import Pill from "../components/Pill.svelte";
  import ProtectionCard from "../components/ProtectionCard.svelte";
  import { app, go } from "../lib/store.svelte";
  import { tr, sev } from "../lib/i18n";
  import { collectorSummary, distinct, groupQuestions, isProblem, isReminder, jobHealth, problemCounts, scoreTone, type Finding } from "../lib/model";

  const d = $derived(app.data);
  const sec = $derived(d?.security ?? null);
  const findings = $derived((d?.findings ?? []) as Finding[]);
  const problems = $derived(findings.filter(isProblem));
  const counts = $derived(problemCounts(findings));
  const reminders = $derived(findings.filter(isReminder).length);
  const crit = $derived(distinct(problems.filter((f) => f.severity === "critical"), 4));
  const high = $derived(distinct(problems.filter((f) => f.severity === "high"), 4));
  const questions = $derived(groupQuestions(d?.questions ?? []));
  const fixes = $derived((d?.fix ?? []) as any[]);
  const coll = $derived(collectorSummary(d?.jobs ?? []));
  const quiet = $derived((d?.jobs ?? []).filter((j: any) => ["stale", "never", "error"].includes(jobHealth(j))).slice(0, 4));
  const tone = $derived(scoreTone(sec?.score));
  const toneVar = $derived(tone === "red" ? "var(--red-700)" : tone === "amber" ? "var(--amber-700)" : tone === "green" ? "var(--green-700)" : "var(--gray-600)");
  const steps = $derived((sec?.next_steps ?? []).slice(0, 5));
  const C = 2 * Math.PI * 44;
  const delta = $derived.by(() => {
    const h = (sec?.history ?? []).filter((p: number[]) => p[0] >= Date.now() / 1000 - 86400);
    return h.length > 1 ? h[h.length - 1][1] - h[0][1] : null;
  });
</script>

{#if !d}
  <div class="empty">
    {tr(app.status.message)}{#if app.status.detail}<br />{app.status.detail}{/if}
    {#if app.error && app.status.phase === "starting"}<br />{app.error}{/if}
  </div>
{:else}
  <div class="flex flex-col gap-8">
    {#if counts.critical}
      <button class="card flex w-full cursor-default items-center gap-4 px-5 py-4 text-left transition-colors hover:bg-gray-100"
              onclick={() => go("findings", { severity: "critical", query: "" })}>
        <span class="grid size-9 place-items-center rounded-full bg-amber-100 text-amber-900"><TriangleAlert size={17} /></span>
        <div class="min-w-0 flex-1">
          <div class="text-label-14">{counts.critical === 1 ? tr("1 critical finding needs attention") : tr("{n} critical findings need attention", { n: counts.critical })}</div>
          <div class="truncate text-copy-13 text-gray-900">{tr("Most urgent: {title}", { title: crit[0]?.title ?? "" })}</div>
        </div>
        <span class="link">{tr("Review")}<ChevronRight size={13} class="ml-0.5 inline -translate-y-px" /></span>
      </button>
    {/if}

    <section class="grid grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)] gap-4 max-lg:grid-cols-1">
      <div class="card flex items-center gap-8 px-8 py-6">
        <svg width="132" height="132" viewBox="0 0 100 100" class="-rotate-90 shrink-0" role="img" aria-label={tr("Security score {n}", { n: sec?.score ?? "?" })}>
          <circle cx="50" cy="50" r="44" fill="none" stroke="var(--gray-200)" stroke-width="7" />
          <circle cx="50" cy="50" r="44" fill="none" stroke={toneVar} stroke-width="7" stroke-linecap="round"
                  stroke-dasharray={C} stroke-dashoffset={C * (1 - Math.max(0, Math.min(100, sec?.score ?? 0)) / 100)}
                  class="ring-fill" />
        </svg>
        <div class="min-w-0">
          <div class="text-label-12 text-gray-900">{tr("Security score")}</div>
          <div class="text-display">{sec?.score ?? "—"}</div>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <span class="text-label-13">{sec?.grade ? sec.grade[0].toUpperCase() + sec.grade.slice(1) : ""}</span>
            {#if delta !== null}
              <span class="pill {delta > 0 ? 'pill-ok' : delta < 0 ? 'pill-high' : 'pill-low'}">{tr("{n} in 24 h", { n: (delta > 0 ? "+" : "") + delta })}</span>
            {/if}
          </div>
          <div class="mt-1 text-copy-13 text-gray-900">{tr("Monitoring coverage {n}%", { n: sec?.coverage ?? "—" })}</div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">{tr("Areas")}<span class="meta">{tr("verified score per area")}</span></div>
        <div class="grid grid-cols-[auto_1fr_auto] items-center gap-x-4 gap-y-2.5 px-5 pb-5">
          {#each sec?.areas ?? [] as a (a.name)}
            {@const t = scoreTone(a.score)}
            <span class="text-copy-13 text-gray-900">{a.name}</span>
            <div class="meter"><i style:width="{a.score ?? 0}%" style:background={t === 'red' ? 'var(--red-700)' : t === 'amber' ? 'var(--amber-700)' : t === 'green' ? 'var(--green-700)' : 'var(--gray-600)'}></i></div>
            <span class="tabular text-right text-label-12 text-gray-900">{a.score === null ? "—" : `${a.score}%`}</span>
          {/each}
        </div>
      </div>
    </section>

    <section>
      <h2 class="mb-3 text-heading-20">{tr("What needs attention")}</h2>
      <div class="grid grid-cols-4 gap-4 max-xl:grid-cols-2 max-md:grid-cols-1">
        {#snippet card(label: string, dot: string, n: number | string, numCls: string, rows: { t: string; s: string }[], empty: string, action: string, onclick: () => void)}
          <div class="card flex flex-col">
            <div class="flex items-center gap-2 px-5 pt-4 text-label-13 text-gray-900"><span class="dot {dot}"></span>{label}</div>
            <div class="px-5 pt-1 pb-4 text-display {numCls}">{n}</div>
            <div class="divide flex-1">
              {#each rows as r}
                <div class="px-5 py-2.5"><div class="truncate text-label-13">{r.t}</div><div class="truncate text-copy-13 text-gray-900">{r.s}</div></div>
              {:else}
                <div class="px-5 py-2.5 text-copy-13 text-gray-900">{empty}</div>
              {/each}
            </div>
            <div class="px-5 pt-2 pb-4"><button class="link" {onclick}>{action}<ChevronRight size={13} class="ml-0.5 inline -translate-y-px" /></button></div>
          </div>
        {/snippet}
        {@render card(sev("critical"), "dot-bad", counts.critical, counts.critical ? "text-amber-900" : "",
          crit.map((f) => ({ t: f.title, s: `${f.job} · ${f.host ?? ""}${f.count > 1 ? " · " + tr("{n} places", { n: f.count }) : ""}` })),
          tr("None open"), tr("Show critical"), () => go("findings", { severity: "critical", query: "" }))}
        {@render card(sev("high"), "dot-warn", counts.high, counts.high ? "text-amber-900" : "",
          high.map((f) => ({ t: f.title, s: `${f.job} · ${f.host ?? ""}${f.count > 1 ? " · " + tr("{n} places", { n: f.count }) : ""}` })),
          tr("None open"), tr("Show high"), () => go("findings", { severity: "high", query: "" }))}
        {@render card(tr("Needs your decision"), "dot-run", questions.length + fixes.length, "",
          [...questions.slice(0, 3).map((q) => ({ t: q.prompt, s: q.ids.length > 1 ? tr("Question · asked {n} times", { n: q.ids.length }) : tr("Question") })),
           ...fixes.slice(0, 2).map((f) => ({ t: f.title, s: tr("Fix proposal · {status}", { status: f.status }) }))],
          tr("Nothing is waiting on you"), tr("Open review"), () => go("review"))}
        {@render card(tr("Collectors reporting"), coll.stale + coll.error ? "dot-warn" : "dot-ok", `${coll.ok}/${coll.total}`, "",
          quiet.map((j: any) => ({ t: j.label, s: jobHealth(j) === "error" ? tr("Error") : tr("Not reporting") })),
          tr("All collectors are fresh"), tr("Open collectors"), () => go("collectors"))}
      </div>
    </section>

    <ProtectionCard />

    {#if steps.length}
      <section class="card">
        <div class="card-head">{tr("Biggest gains next")}<span class="meta">{tr("the first is worth the most")}</span></div>
        <div class="divide">
          {#each steps as s, i}
            <button class="row row-click w-full text-left" onclick={() => go("findings", { query: s.title, severity: null })}>
              <span class="w-5 shrink-0 tabular text-label-13 {i === 0 ? 'text-blue-900' : 'text-gray-700'}">{i + 1}</span>
              <Pill severity={s.severity} />
              <span class="min-w-0 flex-1 truncate text-label-13">{s.title}</span>
              <span class="shrink-0 text-copy-13 text-gray-900">{s.area}</span>
            </button>
          {/each}
        </div>
      </section>
    {/if}
  </div>
{/if}
