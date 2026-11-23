<script lang="ts">
  // Phone alerts. Simple: pair and see your phones. Expert: also the relay,
  // the encryption library, delivery state and device ids.
  import { onMount } from "svelte";
  import PhonePairing from "../components/PhonePairing.svelte";
  import PhoneDevices from "../components/PhoneDevices.svelte";
  import { api, type PhoneDevice, type PhoneStatus } from "../lib/api";
  import { app } from "../lib/store.svelte";
  import { agoT, tr } from "../lib/i18n";
  import { bareUrl } from "../lib/phone";

  let status = $state<PhoneStatus | null>(null);
  let devices = $state<PhoneDevice[]>([]);
  let error = $state("");

  async function load() {
    try {
      const [s, d] = await Promise.all([api.phoneStatus(), api.phoneDevices()]);
      status = s; devices = d.devices; error = "";
    } catch (e) { error = String((e as Error).message ?? e); }
  }
  onMount(load);

  const rows = $derived<[string, string][]>(!status ? [] : [
    [tr("Relay"), status.relay ? bareUrl(status.relay) : status.relay_error],
    [tr("Encryption library"), status.crypto ? tr("Available") : status.crypto_error || tr("Unavailable")],
    [tr("Phones"), status.pending ? tr("{n} active, {p} not activated", { n: status.devices, p: status.pending }) : String(status.devices)],
    [tr("Last delivery"), agoT(status.last_ok)],
    ...(status.last_error ? [[tr("Last error"), status.last_error] as [string, string]] : []),
  ]);
</script>

<div class="mx-auto flex max-w-[680px] flex-col gap-6">
  <div class="px-1">
    <h1 class="text-heading-24">{app.mode === "simple" ? tr("Alerts on your phone") : tr("Phone alerts")}</h1>
    <p class="mt-1 text-copy-14 text-gray-900">
      {app.mode === "simple"
        ? tr("Important alerts, readable only on your paired phone.")
        : tr("Important alerts, readable only on your paired phone.")}
    </p>
  </div>

  {#if error}<div class="card p-4 text-copy-13 text-amber-900 selectable">{error}</div>{/if}

  {#if status && !status.crypto}
    <div class="card p-4 text-copy-13 text-amber-900">{app.mode === "simple" ? tr("Phone alerts cannot be used on this computer yet, because a required part is missing.") : tr("Phone alerts need an encryption library that is missing here.")}{#if app.mode === "expert"} <span class="selectable">{status.crypto_error}</span>{/if}</div>
  {:else}
    <PhonePairing onchange={load} />
  {/if}

  <PhoneDevices {devices} onchange={load} />

  {#if app.mode === "expert" && rows.length}
    <section>
      <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Delivery")}</h2>
      <div class="card divide">
        {#each rows as [k, v]}<div class="row justify-between gap-4"><span class="text-label-13">{k}</span><span class="selectable text-right text-copy-13 text-gray-900">{v}</span></div>{/each}
      </div>
    </section>
  {/if}
</div>
