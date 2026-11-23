<script lang="ts">
  import Sidebar from "./components/Sidebar.svelte";
  import Toolbar from "./components/Toolbar.svelte";
  import SimpleOverview from "./views/SimpleOverview.svelte";
  import Overview from "./views/Overview.svelte";
  import Findings from "./views/Findings.svelte";
  import Collectors from "./views/Collectors.svelte";
  import Review from "./views/Review.svelte";
  import Assistant from "./views/Assistant.svelte";
  import Pricing from "./views/Pricing.svelte";
  import Geo from "./views/Geo.svelte";
  import CoverageView from "./views/Coverage.svelte";
  import World from "./views/World.svelte";
  import Procs from "./views/Procs.svelte";
  import Settings from "./views/Settings.svelte";
  import Phone from "./views/Phone.svelte";
  import Licence from "./views/Licence.svelte";
  import CommandPalette from "./components/CommandPalette.svelte";
  import Toasts from "./components/Toasts.svelte";
  import StatusBanner from "./components/StatusBanner.svelte";
  import { Tooltip } from "bits-ui";
  import { app } from "./lib/store.svelte";
  import { tr } from "./lib/i18n";

  const views = { overview: Overview, findings: Findings, collectors: Collectors, review: Review, assistant: Assistant, geo: Geo, coverage: CoverageView, world: World, procs: Procs, phone: Phone, pricing: Pricing, licence: Licence, settings: Settings };
  const Current = $derived(app.view === "overview" && app.mode === "simple" ? SimpleOverview : views[app.view]);
</script>

<Tooltip.Provider>
<div class="flex h-full">
  <Sidebar />
  <div class="flex min-w-0 flex-1 flex-col">
    <Toolbar />
    <main class="flex-1 overflow-y-auto">
      {#if (app.data?.paused_until ?? 0) * 1000 > Date.now()}
        <div class="mx-auto {app.mode === 'simple' ? 'max-w-[920px] px-8 pt-1 pb-3' : 'mt-6 max-w-[1360px] px-6'}">
          <div class="flex items-center gap-3 rounded-lg bg-amber-100 px-4 py-2.5 text-copy-13 text-amber-900">
            <span class="dot dot-warn"></span>{tr("ARGUS-INSTINCT is taking a break and is not checking your computer. It starts again by itself at {time}.", { time: new Date(app.data.paused_until * 1000).toLocaleTimeString(app.lang, { hour: "2-digit", minute: "2-digit" }) })}
          </div>
        </div>
      {/if}
      {#if app.status.phase !== "live" && app.status.phase !== "starting"}<StatusBanner />{/if}
      <!-- Simple reads as one calm column; Expert uses the whole window. -->
      <div class="mx-auto {app.mode === 'simple' ? 'max-w-[920px] px-8 pt-4 pb-10' : 'max-w-[1360px] px-6 py-6'}">
        {#key app.view}<div class="anim-rise"><Current /></div>{/key}
      </div>
    </main>
  </div>
</div>
<CommandPalette />
</Tooltip.Provider>

<Toasts />
