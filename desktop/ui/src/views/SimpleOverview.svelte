<script lang="ts">
  import { onMount } from "svelte";
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import ShieldAlert from "@lucide/svelte/icons/shield-alert";
  import Eye from "@lucide/svelte/icons/eye";
  import MessageCircle from "@lucide/svelte/icons/message-circle";
  import ListChecks from "@lucide/svelte/icons/list-checks";
  import Sparkles from "@lucide/svelte/icons/sparkles";
  import ChevronRight from "@lucide/svelte/icons/chevron-right";
  import Smartphone from "@lucide/svelte/icons/smartphone";
  import ScanSearch from "@lucide/svelte/icons/scan-search";
  import Pill from "../components/Pill.svelte";
  import ProtectionCard from "../components/ProtectionCard.svelte";
  import { api, type Autopilot, type Protection } from "../lib/api";
  import { app, go, refresh, toast } from "../lib/store.svelte";
  import { tr, agoT } from "../lib/i18n";
  import { collectorSummary, distinct, groupQuestions, isProblem, problemCounts, type Finding } from "../lib/model";
  import { hasGuide, headline, plainFinding } from "../lib/plain";

  let ap = $state<(Autopilot & { health?: { okay: string; monitoring_line: string } }) | null>(null);
  let phones = $state<number | null>(null);
  onMount(async () => { try { ap = await api.autopilot(); } catch { ap = null; } });
  onMount(async () => { try { phones = (await api.phoneStatus()).devices; } catch { phones = null; } });

  // The one big button. It asks ARGUS-INSTINCT for a fresh picture and, where Windows'
  // virus protection can be reached, starts its quick scan too (the same call as the
  // "Check for viruses" button on the protection card). Nothing else is changed.
  let prot = $state<Protection | null>(null);
  let checking = $state(false);
  onMount(async () => { try { prot = await api.protection(); } catch { prot = null; } });
  async function checkNow() {
    checking = true;
    try {
      if (prot?.available) { const r = await api.scan(); toast(r.message ?? tr("Scan started"), "ok"); }
      await refresh();
    } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { checking = false; }
  }
  const paused = $derived((app.data?.paused_until ?? 0) * 1000 > Date.now());

  const d = $derived(app.data);
  const findings = $derived((d?.findings ?? []) as Finding[]);
  const counts = $derived(problemCounts(findings));
  const coll = $derived(collectorSummary(d?.jobs ?? []));
  const look = $derived(counts.critical + counts.high);
  const h = $derived(headline(d?.security?.score, counts.critical, counts.high, coll.stale + coll.error));
  const top = $derived(distinct(findings.filter((f) => isProblem(f) && (f.severity === "critical" || f.severity === "high")), 3));
  const waiting = $derived(groupQuestions(d?.questions ?? []).length + (d?.fix ?? []).length + (ap?.needs_me?.length ?? 0));
  const score = $derived(d?.security?.score as number | undefined);
  const C = 2 * Math.PI * 52;
  const hue = $derived({ ok: "var(--green-700)", warn: "var(--amber-700)", bad: "var(--amber-700)", unknown: "var(--gray-600)" }[h.tone]);
  const soft = $derived({ ok: "var(--green-100)", warn: "var(--amber-100)", bad: "var(--amber-100)", unknown: "var(--gray-100)" }[h.tone]);
</script>

{#if !d}
  <div class="empty">{app.error || tr("Reading ARGUS-INSTINCT…")}</div>
{:else}
  <div class="mx-auto flex max-w-[760px] flex-col gap-7">
    <!-- hero: the answer first, then the one thing to press -->
    <section class="hero anim-rise">
      <div class="hero-aura -top-28 -right-20 size-80 opacity-80" style:background={soft}></div>
      <div class="hero-aura -bottom-32 -left-16 size-72 opacity-50" style:background="var(--blue-100)"></div>
      <div class="relative flex items-center gap-8 px-9 pt-9 pb-7 max-sm:flex-col max-sm:items-start">
        <div class="relative shrink-0">
          <svg width="128" height="128" viewBox="0 0 120 120" class="-rotate-90" role="img" aria-label={tr("Health {n} out of 100", { n: score ?? "?" })}>
            <circle cx="60" cy="60" r="52" fill="none" stroke="var(--gray-200)" stroke-width="7" />
            <circle cx="60" cy="60" r="52" fill="none" stroke={hue} stroke-width="7" stroke-linecap="round"
                    stroke-dasharray={C} stroke-dashoffset={C * (1 - Math.max(0, Math.min(100, score ?? 0)) / 100)} class="ring-fill" />
          </svg>
          <div class="absolute inset-[18px] grid place-items-center rounded-full" style:color={hue} style:background={soft}>
            {#if h.tone === "ok"}<ShieldCheck size={42} strokeWidth={1.6} />{:else}<ShieldAlert size={42} strokeWidth={1.6} />{/if}
          </div>
        </div>
        <div class="min-w-0">
          <h2 class="text-heading-32 text-balance">{tr(h.title, h.vars)}</h2>
          <p class="mt-2 text-[15px] leading-[22px] text-gray-900">{tr(h.body, h.vars)}</p>
          {#if h.partial}<p class="mt-1 text-copy-14 text-amber-900">{tr(h.partial)}</p>{/if}
        </div>
      </div>
      <div class="relative flex flex-wrap items-center gap-x-5 gap-y-3 px-9 pb-8">
        <button class="btn-hero" disabled={checking} onclick={checkNow}>
          <ScanSearch size={19} class={checking ? "animate-pulse" : ""} />{checking ? tr("Checking…") : tr("Check my computer")}
        </button>
        <span class="flex items-center gap-2 text-copy-13 text-gray-900">
          <span class="dot {paused ? 'dot-warn' : 'dot-ok'}"></span>{paused ? tr("On a break") : tr("Watching")}{#if app.updatedAt}{" · "}{tr("last checked {when}", { when: agoT(app.updatedAt / 1000) })}{/if}
        </span>
      </div>
    </section>

    <!-- three plain facts, as grouped rows -->
    <section class="rows">
      <button class="rows-item" onclick={() => go("findings", { severity: null, query: "" })}>
        <span class="tile {look ? 'tile-warn' : 'tile-ok'}"><ListChecks size={19} /></span>
        <span class="min-w-0 flex-1 text-copy-14"><b class="mr-1.5 text-heading-20 tabular">{look}</b>{" "}{look === 1 ? tr("thing worth a look") : tr("things worth a look")}</span>
        <ChevronRight size={16} class="shrink-0 text-gray-600 rtl:rotate-180" />
      </button>
      <button class="rows-item" onclick={() => go("review")}>
        <span class="tile tile-info"><MessageCircle size={19} /></span>
        <span class="min-w-0 flex-1 text-copy-14"><b class="mr-1.5 text-heading-20 tabular">{waiting}</b>{" "}{waiting === 1 ? tr("question is waiting for you") : tr("questions are waiting for you")}</span>
        <ChevronRight size={16} class="shrink-0 text-gray-600 rtl:rotate-180" />
      </button>
      <button class="rows-item" onclick={() => go("collectors")}>
        <span class="tile {coll.stale + coll.error ? 'tile-warn' : 'tile-ok'}"><Eye size={19} /></span>
        <span class="min-w-0 flex-1 text-copy-14"><b class="mr-1.5 text-heading-20 tabular">{coll.ok}<span class="text-label-14 font-normal text-gray-700">{" / "}{coll.total}</span></b>{" "}{tr("checks are up to date")}</span>
        <ChevronRight size={16} class="shrink-0 text-gray-600 rtl:rotate-180" />
      </button>
    </section>

    {#if top.length}
      <section>
        <h3 class="rows-title">{tr("Worth a look first")}</h3>
        <div class="rows">
          {#each top as f, i}
            <button class="rows-item items-start! anim-rise" style:animation-delay="{i * 60}ms"
                    onclick={() => { go("findings", { query: "", severity: null }); app.selected = f; }}>
              <span class="w-[92px] shrink-0 pt-0.5"><Pill severity={f.severity} /></span>
              <span class="min-w-0 flex-1">
                {#if hasGuide(f)}
                  <span class="block text-label-14">{tr(plainFinding(f).means)}</span>
                  <span class="mt-0.5 block text-copy-13 text-gray-900">{tr(plainFinding(f).next)}</span>
                {:else}
                  <span class="block text-label-14">{f.title}</span>
                {/if}
              </span>
              <ChevronRight size={16} class="mt-1 shrink-0 text-gray-600 rtl:rotate-180" />
            </button>
          {/each}
        </div>
      </section>
    {/if}

    <ProtectionCard />

    <section class="rows">
      {#if phones !== null}
        <button class="rows-item" onclick={() => go("phone")}>
          <span class="tile {phones ? 'tile-ok' : 'tile-info'}"><Smartphone size={19} /></span>
          <span class="flex-1 text-label-14">{phones ? (phones === 1 ? tr("Your phone gets alerts") : tr("{n} phones get alerts", { n: phones })) : tr("Get alerts on your phone")}</span>
          <ChevronRight size={16} class="shrink-0 text-gray-600 rtl:rotate-180" />
        </button>
      {/if}
      <button class="rows-item" onclick={() => go("assistant")}>
        <span class="tile tile-info"><Sparkles size={19} /></span>
        <span class="flex-1 text-label-14">{tr("Not sure what something means?")}</span>
        <ChevronRight size={16} class="shrink-0 text-gray-600 rtl:rotate-180" />
      </button>
    </section>
  </div>
{/if}
