<script lang="ts">
  // The app's account of the daemon when it is not simply "watching". Blind
  // collectors are grouped by cause with a count; the names are one click away
  // instead of a paragraph. Grouped, never hidden: every one is in the list.
  import ChevronDown from "@lucide/svelte/icons/chevron-down";
  import Play from "@lucide/svelte/icons/play";
  import { api } from "../lib/api";
  import { groupBlind, onlyEditionLimits, statusKey } from "../lib/blind";
  import { app, go, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";

  const OPEN_KEY = "jarvis.statusOpen";
  let open = $state(readOpen());
  function readOpen() { try { return localStorage.getItem(OPEN_KEY) === "1"; } catch { return false; } }
  function toggle() {
    open = !open;
    try { localStorage.setItem(OPEN_KEY, open ? "1" : "0"); } catch { /* per-viewer convenience only */ }
  }

  const groups = $derived(groupBlind(app.status.blind));
  const calm = $derived(onlyEditionLimits(app.status.blind));
  const head = $derived.by(() => { const k = statusKey(app.status.message); return k.n == null ? tr(k.key) : tr(k.key, { n: k.n }); });
  // Simple says the same groups in everyday words; Expert keeps the shell's own terms.
  const simple = $derived(app.mode === "simple");
  const plainTitle = $derived<Record<string, string>>({ failed: tr("Could not run"), stale: tr("Behind or not started"), admin_sensor: tr("Needs extra permission") });
  const plainHelp = $derived<Record<string, string>>({ failed: "", admin_sensor: tr("These checks need a permission this version does not have, so they see less. This is normal, not a fault.") });
  const title = (g: { kind: string; title: string }) => (simple && plainTitle[g.kind]) || tr(g.title);
  const help = (g: { kind: string; help: string }) => (simple && g.kind in plainHelp ? plainHelp[g.kind] : g.help ? tr(g.help) : "");
  const queued = $state<Record<string, boolean>>({});
  async function again(job: string, label: string) {
    queued[job] = true;
    try { await api.runCollector(job); toast(tr("{name} queued", { name: label }), "ok"); }
    catch (e) { queued[job] = false; toast(String((e as Error)?.message ?? e), "bad"); }
  }
</script>

<div class="mx-auto {simple ? 'max-w-[920px] px-8 pt-1' : 'mt-6 max-w-[1360px] px-6'}" role="status">
  <div class="{simple ? 'rounded-[20px] px-5 py-4' : 'rounded-[10px] px-4 py-3'} text-copy-13 {calm ? 'bg-gray-100 text-gray-1000' : 'bg-amber-100 text-amber-900'}">
    <div class="flex items-start gap-3">
      <span class="dot mt-1.5 shrink-0 {calm ? '' : 'dot-warn'}"></span>
      <div class="min-w-0 flex-1">
        <p class="text-label-13">{head}{#if app.daemon === "down" && app.data}. {tr("Showing the last state it reported.")}{/if}</p>
        {#if groups.length}
          <div class="mt-2 flex flex-wrap items-center gap-1.5">
            {#each groups as g (g.kind)}
              <span class="inline-flex items-center gap-1.5 rounded-full bg-bg-100/70 px-2.5 py-0.5 text-label-12">
                {title(g)}<span class="tabular opacity-70">{g.items.length}</span>
              </span>
            {/each}
          </div>
        {:else if app.status.detail}
          <p class="mt-1 selectable">{app.status.detail}</p>
        {/if}
      </div>
      <div class="flex shrink-0 items-center gap-1.5">
        {#if groups.length}
          <button class="btn btn-sm btn-ghost" aria-expanded={open} onclick={toggle}>
            {open ? tr("Hide") : tr("Show which")}<ChevronDown size={13} class="transition-transform {open ? 'rotate-180' : ''}" />
          </button>
          {#if app.mode === "expert"}<button class="btn btn-sm" onclick={() => go("collectors")}>{tr("See collectors")}</button>{/if}
        {/if}
      </div>
    </div>

    {#if open && groups.length}
      <div class="mt-3 grid gap-4 border-t border-current/10 pt-3 pl-5 md:grid-cols-2 xl:grid-cols-3">
        {#each groups as g (g.kind)}
          <section class="min-w-0">
            <h3 class="text-label-12">{title(g)} <span class="tabular opacity-70">· {g.items.length}</span></h3>
            {#if help(g)}<p class="mt-0.5 text-label-12 font-normal opacity-80">{help(g)}</p>{/if}
            <ul class="mt-1.5 flex flex-col">
              {#each g.items as it (it.job + it.label)}
                <li class="group relative flex h-6 items-center">
                  <span class="min-w-0 flex-1 truncate" title={g.kind === "other" ? `${it.label}: ${it.reason}` : it.label}>
                    {it.label}{#if g.kind === "other"}<span class="opacity-70"> — {it.reason}</span>{/if}
                  </span>
                  {#if it.job && (g.kind === "failed" || g.kind === "stale") && app.mode === "expert"}
                    <button class="btn btn-sm absolute right-0 h-6 opacity-0 group-hover:opacity-100 focus-visible:opacity-100" disabled={queued[it.job]}
                            onclick={() => again(it.job, it.label)} aria-label={`${tr("Run again")}: ${it.label}`}>
                      <Play size={11} />{tr("Run again")}
                    </button>
                  {/if}
                </li>
              {/each}
            </ul>
          </section>
        {/each}
      </div>
    {/if}
  </div>
</div>
