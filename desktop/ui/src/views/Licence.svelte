<script lang="ts">
  // The licence screen: enter a key, buy from here (activates by itself), see and manage the licence.
  // A licence unlocks premium content only (the full review report); monitoring never depends on it.
  import { onDestroy, onMount } from "svelte";
  import { api, type LicenceState } from "../lib/api";
  import { checkKey, PRODUCT } from "../lib/licence";
  import { toast } from "../lib/store.svelte";

  let st = $state<LicenceState | null>(null);
  let loadError = $state("");
  let key = $state("");
  let busy = $state(false);
  let problem = $state("");
  let confirmDeactivate = $state(false);
  let waiting = $state(false);
  let timer: ReturnType<typeof setInterval> | null = null;
  const feedback = $derived(checkKey(key));
  const day = (ts?: number | null) => (ts ? new Date(ts * 1000).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : "no end date");

  // The daemon restarts now and then (the service replaces a stalled one, which takes seconds to
  // minutes). Keep asking, keep the last good state, and only report an error if it never comes back.
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let retries = $state(0);
  const MAX_RETRIES = 40; // about 3 minutes at 5 s
  async function load() {
    try { st = await api.licence(); loadError = ""; retries = 0; if (st.purchase_waiting) startPolling(); }
    catch (e) {
      loadError = String((e as Error).message ?? e);
      if (retries++ < MAX_RETRIES) retryTimer = setTimeout(load, 5000);
    }
  }
  async function run(action: "activate" | "deactivate" | "refresh", k?: string) {
    busy = true; problem = "";
    try {
      const r = await api.licenceAction(action, k);
      if (r.state) st = r.state;
      if (!r.ok) { problem = r.error ?? "That did not work."; return; }
      confirmDeactivate = false;
      if (action === "activate") { key = ""; toast("Licence activated for this computer", "ok"); }
      if (action === "deactivate") toast("This computer's seat is free. Activate the key on the new machine.", "ok");
      if (action === "refresh") toast("Licence checked and renewed", "ok");
    } catch (e) { problem = String((e as Error).message ?? e); }
    finally { busy = false; }
  }
  async function upgrade(plan: "server" | "desktop") {
    busy = true; problem = "";
    try {
      const r = await api.licenceAction("upgrade", undefined, plan);
      if (!r.ok || !r.open) { problem = r.error ?? "Checkout could not be opened."; return; }
      await api.openLicencePage(r.open);
      startPolling();
    } catch (e) { problem = String((e as Error).message ?? e); }
    finally { busy = false; }
  }
  function startPolling() {
    waiting = true;
    if (timer) return;
    timer = setInterval(async () => {
      try {
        const r = await api.licenceAction("poll");
        if (r.active && r.state) { st = r.state; stopPolling(); toast("Thank you. Argus is activated on this computer.", "ok"); }
        else if (!r.ok) { problem = r.error ?? ""; stopPolling(); }
      } catch { /* keep waiting; the daemon may be busy */ }
    }, 5000);
  }
  function stopPolling() { waiting = false; if (timer) clearInterval(timer); timer = null; }
  const open = (url?: string) => url && api.openLicencePage(url).catch((e) => toast(String((e as Error).message ?? e), "bad"));
  onMount(load);
  onDestroy(() => { stopPolling(); if (retryTimer) clearTimeout(retryTimer); });
</script>

<div class="mx-auto flex max-w-[680px] flex-col gap-6">
  <header>
    <h2 class="text-heading-20">Licence</h2>
    <p class="mt-1 text-copy-13 text-gray-900">A licence unlocks the full review report. Monitoring, alerts and evidence work with or without one.</p>
  </header>

  {#if loadError && !st && retries <= MAX_RETRIES}
    <div class="card empty">ARGUS-INSTINCT is starting. Checking the licence again…</div>
  {:else if loadError && !st}
    <div class="card p-5 text-copy-13 text-red-900">Could not read the licence: {loadError}</div>
  {:else if !st}
    <div class="card empty">Reading the licence…</div>
  {:else}
    {#if st.licensed || st.needs_check}
      <section class="card divide" aria-label="Licence status">
        <div class="row justify-between">
          <span class="text-label-14">{st.product ?? "Argus"}</span>
          {#if st.licensed}<span class="pill pill-ok">Active on this computer</span>{:else}<span class="pill pill-medium">Needs checking</span>{/if}
        </div>
        {#if st.needs_check}
          <div class="row text-copy-13 text-amber-900">{st.reason}</div>
        {/if}
        <div class="row justify-between"><span class="text-label-13">Renews or ends</span><span class="selectable text-copy-13 text-gray-900">{day(st.expires_at)}</span></div>
        <div class="row justify-between"><span class="text-label-13">This computer</span><span class="selectable text-copy-13 text-gray-900">{st.label ?? "this computer"}{st.key_hint ? ` · key …${st.key_hint}` : ""}</span></div>
        <div class="row justify-between"><span class="text-label-13">Works offline until</span><span class="text-copy-13 text-gray-900">{day(st.lease_until)}{st.auto_renew === false ? " (automatic renewal off)" : " · renews by itself"}</span></div>
        <div class="row flex-wrap gap-2">
          <button class="btn" disabled={busy} onclick={() => open(st?.links.manage)}>Manage licence</button>
          <button class="btn" disabled={busy} onclick={() => run("refresh")}>Check now</button>
          {#if confirmDeactivate}
            <span class="text-copy-13">Free this computer's seat?</span>
            <button class="btn btn-sm" disabled={busy} onclick={() => run("deactivate")}>Deactivate</button>
            <button class="btn btn-ghost btn-sm" onclick={() => (confirmDeactivate = false)}>Cancel</button>
          {:else}
            <button class="btn btn-ghost" disabled={busy} onclick={() => (confirmDeactivate = true)}>Deactivate…</button>
          {/if}
        </div>
      </section>
    {/if}

    {#if !st.licensed && !st.needs_check}
      {#if st.reason !== "no licence installed"}
        <div class="card p-4 text-copy-13 text-amber-900">{st.reason}</div>
      {/if}
      <section class="card p-5" aria-label="Enter licence key">
        <h3 class="text-label-14">Enter licence key</h3>
        <p class="mt-1 text-copy-13 text-gray-900">Paste the key from your purchase email. It starts with ARGUS-DSK- or ARGUS-SRV-.</p>
        <form class="mt-3 flex flex-wrap gap-2" onsubmit={(e) => { e.preventDefault(); if (feedback.state === "ok") run("activate", feedback.key); }}>
          <input class="input min-w-0 flex-1 font-mono" bind:value={key} placeholder="ARGUS-DSK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
                 aria-label="Licence key" autocomplete="off" spellcheck="false" aria-invalid={feedback.state === "bad"} />
          <button class="btn btn-primary" type="submit" disabled={busy || feedback.state !== "ok"}>{busy ? "Activating…" : "Activate"}</button>
        </form>
        <p class="mt-2 min-h-5 text-copy-13" aria-live="polite">
          {#if feedback.state === "bad"}<span class="text-red-900">{feedback.message}</span>
          {:else if feedback.state === "typing"}<span class="text-gray-900">{feedback.message}</span>
          {:else if feedback.state === "ok"}<span class="text-green-900">Key looks right · {PRODUCT[feedback.plan]}</span>{/if}
        </p>
        {#if problem}<p class="mt-1 text-copy-13 text-red-900" role="alert">{problem}</p>{/if}
        <p class="mt-2 text-copy-13"><button class="btn-ghost text-blue-900 underline" type="button" onclick={() => open(st?.links.recover)}>Lost your key?</button></p>
      </section>

      <section class="card p-5" aria-label="Buy">
        <h3 class="text-label-14">No licence yet?</h3>
        {#if waiting}
          <p class="mt-2 flex items-center gap-2 text-copy-13"><span class="dot dot-run"></span>Waiting for the payment to finish in your browser. This computer activates by itself; no key to type.</p>
          <button class="btn btn-ghost btn-sm mt-2" onclick={stopPolling}>Stop waiting</button>
        {:else}
          <p class="mt-1 text-copy-13 text-gray-900">Buy here and this computer activates by itself when the payment goes through.</p>
          <div class="mt-3 flex flex-wrap gap-2">
            <button class="btn btn-primary" disabled={busy} onclick={() => upgrade("desktop")}>Buy Argus Desktop · $79/year</button>
            <button class="btn" disabled={busy} onclick={() => upgrade("server")}>Buy Argus Server · $50/server/year</button>
          </div>
        {/if}
      </section>
    {/if}
  {/if}
</div>
