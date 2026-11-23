<script lang="ts">
  // Prices from the price book (lib/prices.ts). Buying goes through the licence service at
  // pay.archymedes.xyz: this computer opens a claim, the browser pays, and the computer
  // activates by itself. No seller key is ever on this machine. A licence never turns
  // protection on or off (tests/test_licence_never_gates_core.py).
  import { onMount, onDestroy } from "svelte";
  import { api, type LicenceState } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";
  import Segmented from "../components/Segmented.svelte";
  import { DESKTOP, FLEET_MAX, fleetCents, SERVER_TIERS, usd, yearlySavingCents } from "../lib/prices";
  import { buyPage, checkPromo } from "../lib/licence";

  const PAY = "https://pay.archymedes.xyz";
  let st = $state<LicenceState | null>(null);
  let interval = $state("year");
  let servers = $state(10);
  let busy = $state(false);
  let waiting = $state(false);
  let problem = $state("");
  // Optional promo code. Prices on this page stay the list prices; the licence service checks the
  // code at Stripe when checkout opens and says there if it was not applied.
  let promoText = $state("");
  const promo = $derived(checkPromo(promoText));
  let timer: ReturnType<typeof setInterval> | null = null;

  onMount(async () => { try { st = await api.licence(); if (st.purchase_waiting) poll(); } catch { st = null; } });
  onDestroy(() => { if (timer) clearInterval(timer); });

  const yearly = $derived(interval === "year");
  const desktopCents = $derived(yearly ? DESKTOP.yearCents : DESKTOP.monthCents);
  const fleet = $derived(fleetCents(Math.floor(Number(servers))));
  const fmt = (c: number) => usd(c, app.lang);
  const until = $derived(st?.expires_at ? new Date(st.expires_at * 1000).toLocaleDateString(app.lang) : "");

  async function buyHere() {
    if (promo.state === "bad") { problem = tr("A promo code is up to 40 letters, digits, - or _."); return; }
    busy = true; problem = "";
    try {
      const r = await api.licenceAction("upgrade", undefined, yearly ? "desktop" : "desktop-monthly",
                                        promo.state === "ok" ? promo.code : undefined);
      if (!r.ok || !r.open) { problem = r.error ?? tr("Checkout could not be opened."); return; }
      await api.openLicencePage(r.open);
      poll();
    } catch (e) { problem = String((e as Error).message ?? e); }
    finally { busy = false; }
  }
  function poll() {
    waiting = true;
    if (timer) return;
    timer = setInterval(async () => {
      try {
        const r = await api.licenceAction("poll");
        if (r.active && r.state) { st = r.state; waiting = false; if (timer) clearInterval(timer); timer = null; toast(tr("Licensed"), "ok"); }
      } catch { /* keep waiting; the daemon may be busy */ }
    }, 5000);
  }
  async function website(path: string) {
    if (promo.state === "bad") { toast(tr("A promo code is up to 40 letters, digits, - or _."), "bad"); return; }
    try { await api.openLicencePage(`${PAY}/${path}`); } catch (e) { toast(String((e as Error).message ?? e), "bad"); }
  }
</script>

<div class="mx-auto flex max-w-[880px] flex-col gap-8">
  <header>
    <h2 class="text-heading-24">{tr("Pricing")}</h2>
    <p class="mt-1 text-copy-14 text-gray-900">{tr("A licence adds the full review report. Protection works the same without one.")}</p>
  </header>

  {#if st?.licensed}
    <p class="flex items-center gap-2 text-copy-14" role="status">
      <span class="pill pill-ok">{tr("Active")}</span>
      <span>{st.product ?? ""}{until ? ` · ${tr("until {date}", { date: until })}` : ""}</span>
    </p>
  {/if}

  <div class="grid grid-cols-2 gap-x-10 gap-y-8 max-md:grid-cols-1">
    <!-- Desktop -->
    <section class="flex flex-col border-t-2 border-gray-1000 pt-4" aria-label="Argus Desktop">
      <p class="text-eyebrow text-gray-1000">Argus Desktop</p>
      <div class="mt-4">
        <Segmented items={[{ value: "year", label: tr("Yearly") }, { value: "month", label: tr("Monthly") }]} bind:value={interval} label={tr("Billing period")} />
      </div>
      <p class="mt-5 flex items-baseline gap-2">
        <span class="text-display">{fmt(desktopCents)}</span>
        <span class="text-copy-13 text-gray-900">{yearly ? tr("per computer per year") : tr("per computer per month")}</span>
      </p>
      <p class="mt-1 h-5 text-copy-13 text-green-900">{yearly ? tr("Save ${amount} a year compared with paying monthly", { amount: yearlySavingCents / 100 }) : ""}</p>
      <div class="mt-5">
        {#if waiting}
          <p class="flex items-center gap-2 text-copy-13" role="status"><span class="dot dot-run"></span>{tr("Waiting for payment to complete in your browser…")}</p>
        {:else}
          <button class="btn btn-primary h-10 px-5" disabled={busy || st?.licensed} onclick={buyHere}>{tr("Buy for this computer")}</button>
        {/if}
        {#if problem}<p class="mt-2 text-copy-13 text-red-900" role="alert">{problem}</p>{/if}
      </div>
      <p class="mt-4 text-copy-13 text-gray-900">
        {tr("For a team of up to {n} computers, buy on the website.", { n: DESKTOP.teamMax })}
        <button class="link" onclick={() => website(buyPage(yearly ? "argus-desktop" : "argus-desktop-monthly", promo))}>{tr("Buy on the website")}</button>
      </p>
    </section>

    <!-- Server -->
    <section class="flex flex-col border-t-2 border-gray-1000 pt-4" aria-label="Argus Server">
      <p class="text-eyebrow text-gray-1000">Argus Server</p>
      <p class="mt-4 text-copy-13 text-gray-900">{tr("One key for all your servers. Price per server per year:")}</p>
      <dl class="mt-3 grid grid-cols-[1fr_auto] border-t border-gray-300 text-copy-14">
        {#each SERVER_TIERS as t, i}
          {@const from = i === 0 ? 1 : SERVER_TIERS[i - 1].upTo + 1}
          <dt class="border-b border-gray-300 py-2 tabular text-gray-900">{tr("{a}–{b} servers", { a: from, b: t.upTo })}</dt>
          <dd class="border-b border-gray-300 py-2 text-right tabular text-label-14">{fmt(t.usdCents)}</dd>
        {/each}
      </dl>
      <p class="mt-2 text-copy-13 text-gray-900">{tr("Above {n} servers: enterprise terms by contact.", { n: FLEET_MAX })}</p>
      <label class="mt-5 flex items-center gap-3 text-copy-13">
        <span class="text-gray-900">{tr("Servers")}</span>
        <input class="input w-24 tabular" type="number" min="1" max={FLEET_MAX} bind:value={servers} />
        <span class="ml-auto text-label-14 tabular">{fleet === null ? "—" : tr("{total} a year", { total: fmt(fleet) })}</span>
      </label>
      <div class="mt-5">
        <button class="btn h-10 px-5" onclick={() => website(buyPage("argus-server", promo))}>{tr("Buy on the website")}</button>
        <p class="mt-2 text-copy-13 text-gray-900">{tr("The key arrives by email.")}</p>
      </div>
    </section>
  </div>

  <div class="flex flex-col gap-1 border-t border-gray-300 pt-4">
    <label class="flex flex-wrap items-center gap-3 text-copy-13">
      <span class="text-gray-900">{tr("Promo code (optional)")}</span>
      <input class="input w-56" type="text" maxlength="40" autocomplete="off" autocapitalize="characters" spellcheck="false"
             bind:value={promoText} aria-invalid={promo.state === "bad"} />
    </label>
    {#if promo.state === "bad"}
      <p class="text-copy-13 text-red-900" role="alert">{tr("A promo code is up to 40 letters, digits, - or _.")}</p>
    {:else}
      <p class="text-copy-13 text-gray-900">{tr("Prices shown are before any promo code. The code is checked at checkout, where you can also enter one.")}</p>
    {/if}
  </div>

  <p class="text-copy-13 text-gray-900">{tr("Payment by Stripe. Card details never reach ARGUS-INSTINCT.")}</p>
</div>
