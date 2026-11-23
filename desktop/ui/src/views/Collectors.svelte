<script lang="ts">
  import Play from "@lucide/svelte/icons/play";
  import { api } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { tr, sev, agoT } from "../lib/i18n";
  import { t } from "../lib/words";
  import { ago, collectorSummary, every, jobHealth, type Job } from "../lib/model";

  const jobs = $derived((app.data?.jobs ?? []) as Job[]);
  const sum = $derived(collectorSummary(jobs));
  const order = { error: 0, never: 1, stale: 2, running: 3, ok: 4 } as const;
  const sorted = $derived([...jobs].sort((a, b) => order[jobHealth(a)] - order[jobHealth(b)] || a.label.localeCompare(b.label)));
  let busy = $state<Record<string, boolean>>({});

  async function run(j: Job) {
    busy[j.name] = true;
    try { await api.runCollector(j.name); toast(tr("{name} queued", { name: j.label }), "ok"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy[j.name] = false; }
  }
  const label = $derived({ ok: tr("Fresh"), running: tr("Running"), stale: tr("Late"), never: tr("Never ran"), error: tr("Error") });
  const dot = { ok: "dot-ok", running: "dot-run", stale: "dot-warn", never: "dot-warn", error: "dot-bad" } as const;
</script>

<div class="flex flex-col gap-4">
  {#if app.mode === "simple"}<p class="text-copy-14 text-gray-900">{t("checks.intro")}</p>{/if}
  <div class="grid grid-cols-3 gap-4">
    {#each [[t("checks.fresh"), sum.ok, "text-green-900"], [t("checks.late"), sum.stale, sum.stale ? "text-amber-900" : ""], [t("checks.errors"), sum.error, sum.error ? "text-amber-900" : ""]] as [k, n, c]}
      <div class="card px-5 py-4"><div class="text-label-13 text-gray-900">{k}</div><div class="mt-1 text-display text-[32px] leading-[36px] {c}">{n}</div></div>
    {/each}
  </div>
  <div class="card overflow-hidden">
    <div class="divide">
      {#each sorted as j (j.name)}
        {@const h = jobHealth(j)}
        <div class="row">
          <span class="dot {dot[h]}" title={label[h]}></span>
          <div class="min-w-0 flex-1">
            <div class="truncate text-label-13">{j.label}</div>
            <div class="truncate text-copy-13 {h === 'error' ? 'text-amber-900' : 'text-gray-900'}">
              {h === "error" ? (app.mode === "simple" ? tr("This check could not finish.") : (j.error ?? "").trim().split("\n").pop()) : app.mode === "simple" ? `${label[h]} · ${tr("last checked {when}", { when: agoT(j.ts) })}` : `${label[h]} · ${agoT(j.ts)} · ${tr("every {n}", { n: every(j.interval) })}`}
            </div>
          </div>
          {#if app.mode === "expert"}<span class="tag max-md:hidden">{j.name}</span>{/if}
          <button class="btn btn-sm" disabled={busy[j.name] || j.running} onclick={() => run(j)}>
            <Play size={12} />{j.running ? (app.mode === "simple" ? tr("Checking…") : tr("Running")) : t("checks.run")}
          </button>
        </div>
      {/each}
    </div>
  </div>
</div>
