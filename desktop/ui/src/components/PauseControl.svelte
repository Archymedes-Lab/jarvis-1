<script lang="ts">
  import Pause from "@lucide/svelte/icons/pause";
  import Play from "@lucide/svelte/icons/play";
  import { DropdownMenu } from "bits-ui";
  import { api } from "../lib/api";
  import { app, refresh, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";

  const lengths: [number, string][] = [[15, "15 minutes"], [60, "1 hour"], [240, "4 hours"], [1440, "24 hours"]];
  const until = $derived((app.data?.paused_until ?? 0) as number);
  const paused = $derived(until * 1000 > Date.now());
  let busy = $state(false);

  async function pause(m: number) {
    busy = true;
    try { await api.pause(m); toast(tr("ARGUS-INSTINCT is taking a break. It starts again by itself."), "ok"); await refresh(); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  async function resume() {
    busy = true;
    try { await api.resume(); toast(tr("ARGUS-INSTINCT is watching again"), "ok"); await refresh(); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
</script>

{#if paused}
  <button class="btn btn-sm" disabled={busy} onclick={resume}><Play size={13} />{app.mode === "simple" ? tr("Start watching again") : tr("Resume")}</button>
{:else}
  <DropdownMenu.Root>
    <DropdownMenu.Trigger class="btn btn-sm" disabled={busy || app.daemon !== "live"}>
      <Pause size={13} />{app.mode === "simple" ? tr("Take a break") : tr("Pause")}
    </DropdownMenu.Trigger>
    <DropdownMenu.Portal>
      <DropdownMenu.Content class="popover z-50 min-w-[220px] p-1.5" align="end" sideOffset={6}>
        <p class="px-2.5 py-1.5 text-copy-13 text-gray-900">{tr("While paused, ARGUS-INSTINCT does not check your computer. It starts again by itself.")}</p>
        {#each lengths as [m, label]}
          <DropdownMenu.Item class="menu-item" onSelect={() => pause(m)}>{tr(label)}</DropdownMenu.Item>
        {/each}
      </DropdownMenu.Content>
    </DropdownMenu.Portal>
  </DropdownMenu.Root>
{/if}
