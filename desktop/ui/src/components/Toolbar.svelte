<script lang="ts">
  import Search from "@lucide/svelte/icons/search";
  import RotateCw from "@lucide/svelte/icons/rotate-cw";
  import IconButton from "./IconButton.svelte";
  import Segmented from "./Segmented.svelte";
  import PauseControl from "./PauseControl.svelte";
  import { app, refresh, setMode, type Mode } from "../lib/store.svelte";
  import { NAV } from "../lib/nav";
  import { t, type Key } from "../lib/words";
  import { tr } from "../lib/i18n";
  import { scoreTone } from "../lib/model";

  const sec = $derived(app.data?.security);
  const tone = $derived(scoreTone(sec?.score));
  const title = $derived(NAV.some((n) => n.view === app.view) ? t(`nav.${app.view}` as Key) : "");

  function onKey(e: KeyboardEvent) {
    const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
    if ((e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !typing)) {
      e.preventDefault(); app.palette = true;
    }
  }
</script>

<svelte:window onkeydown={onKey} />

<header class="material sticky top-0 z-10 flex items-center gap-4 {app.mode === 'simple' ? 'h-16 px-8' : 'h-13 border-b border-gray-300 px-6'}">
  <div class="flex shrink-0 items-center gap-3">
    <h1 class="{app.mode === 'simple' ? 'text-heading-24' : 'text-heading-16'} whitespace-nowrap">{title}</h1>
    {#if sec && app.mode === "expert"}
      <span class="pill max-xl:hidden {tone === 'red' ? 'pill-critical' : tone === 'amber' ? 'pill-high' : 'pill-ok'}">
        {tr("Score {n}", { n: sec.score })}{sec.state === "verifying" ? " · " + tr("re-checking") : ""}
      </span>
    {/if}
  </div>
  <button class="input mx-auto flex h-9 min-w-0 flex-1 {app.mode === 'simple' ? 'max-w-[380px] rounded-full!' : 'max-w-[480px]'} cursor-default items-center gap-2 text-gray-700" onclick={() => (app.palette = true)} aria-label={tr("Search")}>
    <Search size={15} class="shrink-0" /><span class="min-w-0 flex-1 truncate text-left">{app.mode === "simple" ? tr("Search or jump to a page") : tr("Search or jump to…")}</span><span class="kbd max-md:hidden">Ctrl K</span>
  </button>
  <div class="flex shrink-0 items-center gap-1.5">
    <Segmented items={[{ value: "simple", label: tr("Simple") }, { value: "expert", label: tr("Expert") }]} label={tr("Detail level")}
               bind:value={() => app.mode, (v) => setMode((v || app.mode) as Mode)} />
    <PauseControl />
    <IconButton label={tr("Refresh now")} onclick={refresh} disabled={app.loading}>
      <RotateCw size={15} class={app.loading ? "animate-spin" : ""} />
    </IconButton>
  </div>
</header>
