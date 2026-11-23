<script lang="ts">
  // Paired phones: send a test, stop alerts to one (revoke). Key material never
  // reaches this page; the daemon lists id, name, dates and state only.
  import { api, type PhoneDevice } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { agoT, tr } from "../lib/i18n";

  let { devices, onchange = () => {} }: { devices: PhoneDevice[]; onchange?: () => void } = $props();
  let busy = $state(false);
  let arming = $state<string | null>(null);

  const shown = $derived(devices.filter((d) => !d.revoked_at || app.mode === "expert"));
  const active = $derived(devices.filter((d) => !d.revoked_at).length);

  async function test() {
    busy = true;
    try { const r = await api.phoneTest(); toast(r.ok ? tr("Test sent. Check your phone.") : (r.message ?? tr("Test failed")), r.ok ? "ok" : "bad"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }

  async function revoke(dev: string) {
    if (arming !== dev) { arming = dev; return; }       // second click confirms
    arming = null;
    busy = true;
    try { const r = await api.phoneRevoke(dev); toast(r.message ?? tr("Removed"), r.ok ? "ok" : "bad"); onchange(); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
</script>

<section>
  <div class="mb-2 flex items-center px-1">
    <h2 class="flex-1 text-label-13 text-gray-900">{app.mode === "simple" ? tr("Your phones") : tr("Paired devices")}</h2>
    {#if active}<button class="btn btn-sm" disabled={busy} onclick={test}>{tr("Send a test")}</button>{/if}
  </div>
  <div class="card divide">
    {#each shown as d (d.dev)}
      <div class="row gap-4">
        <div class="min-w-0 flex-1">
          <p class="text-label-13">{d.name}</p>
          <p class="text-copy-13 text-gray-900">
            {tr("Paired {when}", { when: agoT(d.paired_at) })}
            {#if d.revoked_at} · {tr("removed")}{:else if d.pending} · <span class="text-amber-900">{tr("not activated, pair it again")}</span>{/if}
            {#if app.mode === "expert"} · <span class="selectable font-mono">{d.dev.slice(0, 10)}</span>{/if}
          </p>
        </div>
        {#if !d.revoked_at}
          <button class="btn btn-sm {arming === d.dev ? 'btn-primary' : 'btn-ghost'}" disabled={busy} onclick={() => revoke(d.dev)}>
            {arming === d.dev ? tr("Click again to remove") : tr("Remove")}
          </button>
        {/if}
      </div>
    {:else}
      <div class="row text-copy-13 text-gray-900">{tr("No phone is paired yet.")}</div>
    {/each}
  </div>
</section>
