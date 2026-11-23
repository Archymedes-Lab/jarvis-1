<script lang="ts">
  // Pair a phone through the sealed relay. The daemon runs the state machine
  // (jarvis/response/notify/pairing.py); this component only shows its state.
  // A phone is paired only when the owner compares the 6-digit code shown here
  // with the one on the phone and clicks "Codes match", which sends that exact
  // code back. Polling runs only while waiting for the phone and stops when the
  // component goes away.
  import { onDestroy, onMount } from "svelte";
  import Smartphone from "@lucide/svelte/icons/smartphone";
  import { api, type Pairing } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";
  import { bareUrl, clock, live, spacedSas, tone } from "../lib/phone";

  let { onchange = () => {} }: { onchange?: () => void } = $props();

  let p = $state<Pairing | null>(null);
  let busy = $state(false);
  let left = $state(0);
  let timer: ReturnType<typeof setInterval> | undefined;
  let ticker: ReturnType<typeof setInterval> | undefined;
  const POLL_MS = 3000;

  function show(next: Pairing | null) {
    const was = p?.state;
    p = next;
    left = next?.remaining ?? 0;
    if (next?.state === "waiting") { if (!timer) timer = setInterval(poll, POLL_MS); }
    else stopPolling();
    if (was && next && was !== next.state && !live(next.state)) onchange();
  }
  function stopPolling() { if (timer) { clearInterval(timer); timer = undefined; } }

  async function poll() {
    if (!p || p.state !== "waiting") return stopPolling();
    try { show(await api.pairPoll(p.session)); }
    catch (e) { stopPolling(); toast(String((e as Error).message ?? e), "bad"); p = null; }
  }

  async function start() {
    busy = true;
    try { show(await api.pairStart()); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }

  async function answer(same: boolean) {
    if (!p?.sas) return;
    busy = true;
    try { show(await api.pairConfirm(p.session, p.sas, same)); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }

  async function cancel() {
    if (!p) return;
    busy = true;
    try { show(await api.pairCancel(p.session)); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }

  onMount(async () => {
    try { const r = await api.pairCurrent(); if (r.pairing && live(r.pairing.state)) show(r.pairing); } catch { /* nothing to resume */ }
    ticker = setInterval(() => { if (left > 0) left -= 1; }, 1000);
  });
  onDestroy(() => { stopPolling(); if (ticker) clearInterval(ticker); });

  const simple = $derived(app.mode === "simple");
</script>

<div class="card p-6">
  {#if !p || !live(p.state)}
    {#if p}
      <div class="mb-4 flex items-start gap-2.5 rounded-lg px-4 py-3 text-copy-13 {tone(p.state) === 'ok' ? 'bg-green-100 text-green-900' : 'bg-amber-100 text-amber-900'}" role="status">
        <span class="dot mt-1.5 {tone(p.state) === 'ok' ? 'dot-ok' : 'dot-warn'}"></span>
        <span>
          {#if p.state === "paired"}{tr("Paired with {name}.", { name: p.name ?? "phone" })}
          {:else if p.state === "rejected"}{tr("Not paired. If the codes were different, someone may be interfering. Try again.")}
          {:else if p.state === "expired"}{tr("The 10 minutes ran out. Start again when your phone is ready.")}
          {:else if p.state === "cancelled"}{tr("Pairing cancelled.")}
          {:else}{tr("Pairing did not work.")}{/if}
          {#if p.message && (p.state === "error" || p.warning || !simple)}<span class="mt-1 block selectable">{p.message}</span>{/if}
        </span>
      </div>
    {/if}
    <div class="flex items-center gap-4 max-sm:flex-col max-sm:items-start">
      <span class="grid size-11 shrink-0 place-items-center rounded-xl bg-blue-100 text-blue-900"><Smartphone size={22} /></span>
      <div class="min-w-0 flex-1">
        <p class="text-label-14">{simple ? tr("Get alerts on your phone") : tr("Pair a phone")}</p>
        <p class="mt-0.5 text-copy-13 text-gray-900">
          {simple ? tr("When something needs you, your phone tells you, even when you are away from this computer.")
                  : tr("Alerts are end-to-end encrypted to each phone; the relay only passes sealed messages along.")}
        </p>
      </div>
      <button class="btn btn-primary shrink-0" disabled={busy} onclick={start}>{p ? tr("Pair again") : tr("Pair a phone")}</button>
    </div>
  {:else if p.state === "waiting"}
    <ol class="flex flex-col gap-4 text-copy-14">
      <li><span class="text-label-14">1.</span> {tr("On your phone, open {url} and choose “Add a server”.", { url: bareUrl(p.relay) })}</li>
      <li>
        <span class="text-label-14">2.</span> {tr("Enter this code:")}
        <div class="mt-3 select-all rounded-xl bg-gray-100 px-6 py-5 text-center font-mono text-[40px] leading-[48px] tracking-[0.12em] tabular" aria-label={tr("Pairing code")}>{p.code}</div>
      </li>
    </ol>
    <div class="mt-4 flex items-center gap-3 text-copy-13 text-gray-900">
      <span class="dot dot-run"></span>
      <span class="flex-1">{tr("Waiting for your phone… {time} left", { time: clock(left) })}</span>
      <button class="btn btn-ghost btn-sm" disabled={busy} onclick={cancel}>{tr("Cancel")}</button>
    </div>
    {#if p.notice && !simple}<p class="mt-2 text-copy-13 text-amber-900 selectable">{p.notice}</p>{/if}
  {:else}
    <p class="text-label-14">{tr("“{name}” wants to receive alerts from this computer.", { name: p.name ?? "phone" })}</p>
    <p class="mt-1 text-copy-13 text-gray-900">{tr("Your phone now shows a 6-digit code. Pair only if it is exactly the same as this one:")}</p>
    <div class="my-5 rounded-xl bg-gray-100 px-6 py-5 text-center font-mono text-[44px] leading-[52px] tracking-[0.18em] tabular" aria-label={tr("Comparison code")}>{spacedSas(p.sas)}</div>
    <div class="flex flex-wrap gap-2">
      <button class="btn btn-primary" disabled={busy || p.state !== "claimed"} onclick={() => answer(true)}>{tr("Codes match")}</button>
      <button class="btn" disabled={busy || p.state !== "claimed"} onclick={() => answer(false)}>{tr("They don't match")}</button>
    </div>
    {#if !simple && p.device}<p class="mt-3 text-copy-13 text-gray-700 selectable">{tr("Device")} {p.device}</p>{/if}
  {/if}
</div>
