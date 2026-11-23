<script lang="ts">
  import { Command, Dialog } from "bits-ui";
  import Search from "@lucide/svelte/icons/search";
  import CornerDownLeft from "@lucide/svelte/icons/corner-down-left";
  import Play from "@lucide/svelte/icons/play";
  import Globe from "@lucide/svelte/icons/globe";
  import { api } from "../lib/api";
  import { app, go, openInBrowser, toast, type View } from "../lib/store.svelte";
  import { inApp } from "../lib/api";
  import { distinct, filterFindings, sentence, type Finding, type Job } from "../lib/model";
  import { NAV } from "../lib/nav";
  import Pill from "./Pill.svelte";
  import { tr } from "../lib/i18n";
  import { t, type Key } from "../lib/words";

  let search = $state("");
  // One row per distinct finding, with how many places it occurs.
  const findings = $derived(search.trim() ? distinct(filterFindings((app.data?.findings ?? []) as Finding[], { query: search }), 8) : []);
  const jobs = $derived(((app.data?.jobs ?? []) as Job[]).filter((j) =>
    search.trim() && `${j.label} ${j.name}`.toLowerCase().includes(search.trim().toLowerCase())).slice(0, 5));

  function close() { app.palette = false; search = ""; }
  function open(view: View) { go(view); close(); }
  function showFinding(f: Finding & { count?: number }) {
    // Several occurrences: show them all in the list; one: open its detail.
    if ((f.count ?? 1) > 1) { go("findings", { query: f.title, severity: null }); close(); return; }
    go("findings", { query: "", severity: null }); app.selected = f; close();
  }
  const browserLabel = $derived(tr("Open in your browser"));
  const showBrowser = $derived(inApp && (!search.trim() || browserLabel.toLowerCase().includes(search.trim().toLowerCase())
    || "browser".includes(search.trim().toLowerCase())));
  function browser() { close(); void openInBrowser("dashboard"); }
  function searchAll() { go("findings", { query: search.trim(), severity: null }); close(); }
  async function run(j: Job) {
    close();
    try { await api.runCollector(j.name); toast(tr("{name} queued", { name: j.label }), "ok"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
  }
</script>

<Dialog.Root bind:open={app.palette} onOpenChange={(o) => { if (!o) search = ""; }}>
  <Dialog.Portal>
    <Dialog.Overlay class="overlay" />
    <Dialog.Content class="popover fixed top-[14vh] left-1/2 z-50 w-[640px] max-w-[calc(100vw-32px)] -translate-x-1/2 overflow-hidden p-0 anim-rise">
      <Dialog.Title class="sr-only">{tr("Search ARGUS-INSTINCT")}</Dialog.Title>
      <!-- The daemon's findings are filtered here by our own matcher, so the
           palette's built-in fuzzy filter is off. -->
      <Command.Root shouldFilter={false} loop>
        <div class="flex items-center gap-2.5 border-b border-gray-300 px-4">
          <Search size={16} class="text-gray-700" />
          <Command.Input bind:value={search} placeholder={app.mode === "simple" ? tr("Search or jump to a page") : tr("Search findings, collectors, or jump to a view")} class="h-13 flex-1 bg-transparent text-copy-14 outline-none placeholder:text-gray-700" />
          <span class="kbd">Esc</span>
        </div>
        <Command.List class="max-h-[420px] overflow-y-auto p-2">
          <Command.Viewport>
            <Command.Empty class="empty py-8">{tr("No matches.")}</Command.Empty>
            {#if search.trim()}
              <Command.Group>
                <Command.GroupItems>
                  <Command.Item value="search-all" onSelect={searchAll} class="menu-item h-10">
                    <Search size={15} class="text-gray-700" /><span class="flex-1">{tr("Show all findings matching “{q}”", { q: search.trim() })}</span><CornerDownLeft size={14} class="text-gray-700" />
                  </Command.Item>
                </Command.GroupItems>
              </Command.Group>
            {/if}
            {#if findings.length}
              <Command.Group>
                <Command.GroupHeading class="px-2 pt-3 pb-1.5 text-label-12 text-gray-700">{tr("Findings")}</Command.GroupHeading>
                <Command.GroupItems>
                  {#each findings as f, i (i)}
                    <Command.Item value={`finding-${i}`} onSelect={() => showFinding(f)} class="menu-item h-10">
                      <span class="{app.mode === 'simple' ? 'w-[112px]' : 'w-[76px]'} shrink-0"><Pill severity={f.severity} /></span>
                      <span class="min-w-0 flex-1 truncate">{f.title}</span>
                      {#if f.count > 1}<span class="tabular text-label-12 text-gray-700">{tr("{n} places", { n: f.count })}</span>{/if}
                      <span class="tag">{f.job}</span>
                    </Command.Item>
                  {/each}
                </Command.GroupItems>
              </Command.Group>
            {/if}
            {#if jobs.length}
              <Command.Group>
                <Command.GroupHeading class="px-2 pt-3 pb-1.5 text-label-12 text-gray-700">{tr("Run a collector")}</Command.GroupHeading>
                <Command.GroupItems>
                  {#each jobs as j (j.name)}
                    <Command.Item value={`job-${j.name}`} onSelect={() => run(j)} class="menu-item h-10">
                      <Play size={14} class="text-gray-700" /><span class="flex-1 truncate">{j.label}</span><span class="tag">{j.name}</span>
                    </Command.Item>
                  {/each}
                </Command.GroupItems>
              </Command.Group>
            {/if}
            <Command.Group>
              <Command.GroupHeading class="px-2 pt-3 pb-1.5 text-label-12 text-gray-700">{tr("Go to")}</Command.GroupHeading>
              <Command.GroupItems>
                {#each NAV.filter((n) => !search.trim() || t(`nav.${n.view}` as Key).toLowerCase().includes(search.trim().toLowerCase())) as n (n.view)}
                  <Command.Item value={`view-${n.view}`} onSelect={() => open(n.view)} class="menu-item h-10">
                    <n.icon size={15} class="text-gray-700" /><span class="flex-1">{t(`nav.${n.view}` as Key)}</span>
                  </Command.Item>
                {/each}
              </Command.GroupItems>
            </Command.Group>
            {#if showBrowser}
              <Command.Group>
                <Command.GroupHeading class="px-2 pt-3 pb-1.5 text-label-12 text-gray-700">{tr("Actions")}</Command.GroupHeading>
                <Command.GroupItems>
                  <Command.Item value="open-browser" onSelect={browser} class="menu-item h-10">
                    <Globe size={15} class="text-gray-700" /><span class="flex-1">{browserLabel}</span>
                  </Command.Item>
                </Command.GroupItems>
              </Command.Group>
            {/if}
          </Command.Viewport>
        </Command.List>
      </Command.Root>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
