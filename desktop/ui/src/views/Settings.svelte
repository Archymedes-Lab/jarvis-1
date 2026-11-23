<script lang="ts">
  import { onMount } from "svelte";
  import Segmented from "../components/Segmented.svelte";
  import Select from "../components/Select.svelte";
  import { api, inApp, type AppSettings, type Autopilot, type LicenceState } from "../lib/api";
  import { t } from "../lib/words";
  import { LANGS, tr } from "../lib/i18n";
  import { app, checkUpdate, go, openInBrowser, setLang, setMode, setTheme, toast, type Mode, type Theme } from "../lib/store.svelte";
  const themes: [Theme, string][] = [["auto", "Automatic"], ["light", "Light"], ["dark", "Dark"]];

  let ap = $state<Autopilot | null>(null);
  let bill = $state<LicenceState | null>(null);
  let prefs = $state<AppSettings | null>(null);
  onMount(async () => {
    try { ap = await api.autopilot(); } catch { ap = null; }
    try { bill = await api.licence(); } catch { bill = null; }
    if (inApp) { try { prefs = await api.getSettings(); } catch { prefs = null; } }
  });
  async function flip(key: keyof AppSettings) {
    if (!prefs) return;
    const next = { ...prefs, [key]: !prefs[key] };
    try { prefs = await api.setSettings(next); toast(tr("Saved"), "ok"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
  }
  async function toggleAuto() {
    if (!ap?.policy) return;
    const on = !ap.policy.auto_handle;
    try { await api.setAutoHandle(on); ap = await api.autopilot(); toast(on ? tr("Auto-handle is on") : tr("Auto-handle is off"), "ok"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
  }
  const licence = $derived(!bill ? tr("Unavailable") : bill.licensed ? tr("Active") : tr("Not licensed"));
  const days = $derived(ap?.policy?.min_age_days ?? 3);
</script>

<div class="mx-auto flex max-w-[680px] flex-col gap-6">
  {#snippet group(title: string, rows: [string, string][])}
    <section>
      <h2 class="mb-2 px-1 text-label-13 text-gray-900">{title}</h2>
      <div class="card divide">
        {#each rows as [k, v]}<div class="row justify-between gap-4"><span class="text-label-13">{k}</span><span class="selectable text-right text-copy-13 text-gray-900">{v}</span></div>{/each}
      </div>
    </section>
  {/snippet}

  {#if inApp}
    <section>
      <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Updates")}</h2>
      <div class="card divide">
        <div class="row justify-between gap-4">
          <span class="text-label-13">{tr("This version")}</span>
          <span class="selectable text-copy-13 text-gray-900">{app.update?.current ?? "…"}</span>
        </div>
        <div class="row justify-between gap-4">
          <span class="text-label-13">{tr("Newest version")}</span>
          <span class="selectable text-copy-13 {app.update?.newer ? 'text-blue-900' : 'text-gray-900'}">
            {#if !app.update}{tr("Checking…")}{:else if !app.update.enabled}{tr("Update checks are turned off on this computer.")}
            {:else if app.update.latest}{app.update.latest}{app.update.newer ? "" : ` · ${tr("Up to date")}`}
            {:else}{tr("Could not check for updates.")}{/if}
          </span>
        </div>
        <div class="row justify-end gap-2">
          <button class="btn btn-sm" disabled={app.updateChecking} onclick={() => checkUpdate(true)}>{app.updateChecking ? tr("Checking…") : tr("Check now")}</button>
          {#if app.update?.newer}
            <button class="btn btn-sm btn-accent" onclick={() => api.openDownloadPage().catch(() => {})}>{tr("Get the update")}</button>
          {/if}
        </div>
      </div>
      <p class="mt-2 px-1 text-copy-13 text-gray-900">{tr("Checks one public file. Sends nothing, installs nothing.")}</p>
    </section>
  {/if}

  {#if inApp}
    <section>
      <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Browser")}</h2>
      <div class="card row justify-between gap-4">
        <div>
          <p class="text-label-13">{tr("Open in your browser")}</p>
          <p class="mt-0.5 text-copy-13 text-gray-900">{app.mode === "simple" ? tr("See everything in your browser too. It connects by itself.") : tr("See everything in your browser too. It pairs by itself; there is no token to copy.")}</p>
        </div>
        <button class="btn btn-sm btn-accent shrink-0" onclick={() => openInBrowser("dashboard")}>{tr("Open")}</button>
      </div>
    </section>
  {/if}

  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Language")}</h2>
    <div class="card row justify-between gap-4">
      <div>
        <p class="text-label-13">{tr("Interface language")}</p>
      </div>
      <Select items={LANGS.map((l) => ({ value: l.code, label: l.name }))} label={tr("Interface language")} width="w-44"
              bind:value={() => app.lang, (v) => setLang(v || app.lang)} />
    </div>
  </section>

  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Detail level")}</h2>
    <div class="card row justify-between gap-4">
      <div>
        <p class="text-label-13">{app.mode === "simple" ? tr("Simple") : tr("Expert")}</p>
        <p class="mt-0.5 text-copy-13 text-gray-900">{t("settings.mode.sub")}</p>
      </div>
      <Segmented items={[{ value: "simple", label: tr("Simple") }, { value: "expert", label: tr("Expert") }]} label={tr("Detail level")}
                 bind:value={() => app.mode, (v) => setMode((v || app.mode) as Mode)} />
    </div>
  </section>

  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Appearance")}</h2>
    <div class="card row justify-between">
      <span class="text-label-13">{tr("Theme")}</span>
      <Segmented items={themes.map(([v, l]) => ({ value: v, label: tr(l) }))}
                 label={tr("Theme")} bind:value={() => app.theme, (v) => setTheme((v || app.theme) as Theme)} />
    </div>
  </section>

  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Review")}</h2>
    <div class="card divide">
      <div class="row justify-between gap-4">
        <div>
          <p class="text-label-13">{t("review.auto")}</p>
          <p class="mt-0.5 text-copy-13 text-gray-900">{app.mode === "simple" ? tr("If nothing changes for {n} days, small items that only need your OK are accepted for you and written down. Urgent items always wait for you.", { n: days }) : tr("After {n} unchanged days, items that only need your OK are accepted and logged. Never critical.", { n: days })}</p>
        </div>
        {#if ap?.policy}
          <input type="checkbox" checked={ap.policy.auto_handle} onchange={toggleAuto} aria-label={t("review.auto")} />
        {:else}<span class="text-copy-13 text-gray-900">{tr("Needs the newer ARGUS-INSTINCT service")}</span>{/if}
      </div>
      <div class="row justify-between"><span class="text-label-13">{app.mode === "simple" ? tr("Urgent items") : tr("Critical findings")}</span><span class="text-copy-13 text-gray-900">{tr("Always ask")}</span></div>
      <div class="row justify-between"><span class="text-label-13">{app.mode === "simple" ? tr("Fixing problems") : tr("Applying a fix")}</span><span class="text-copy-13 text-gray-900">{app.mode === "simple" ? tr("This app never changes your computer for you") : tr("Never from this app")}</span></div>
    </div>
  </section>

  {@render group(tr("Assistant"), [
    [tr("Where answers come from"), app.mode === "simple" ? tr("What ARGUS-INSTINCT has seen on your computer, plus a built-in safety guide") : tr("ARGUS-INSTINCT's own data and a built-in safety guide; no extra software needed")],
    [tr("Where it runs"), app.mode === "simple" ? tr("Only on your computer. Nothing is sent anywhere else.") : tr("This computer only; nothing is sent to other addresses")],
    [tr("What it can do"), app.mode === "simple" ? tr("It explains things. It never changes anything on your computer.") : tr("Reads and explains; it cannot act on what it says")],
  ])}

  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Licence")}</h2>
    <div class="card row justify-between">
      <span class="text-label-13">{licence}</span>
      <button class="btn btn-sm" onclick={() => go("pricing")}>{tr("Open pricing")}</button>
    </div>
  </section>

  {#if inApp}
  <section>
    <h2 class="mb-2 px-1 text-label-13 text-gray-900">{tr("Notifications")}</h2>
    <div class="card divide">
      {#each [["notify_findings", "settings.notify.findings"], ["notify_health", "settings.notify.health"], ["notify_outage", "settings.notify.outage"]] as [k, key]}
        <div class="row justify-between gap-4">
          <div>
            <p class="text-label-13">{t(key as any)}</p>
            <p class="mt-0.5 text-copy-13 text-gray-900">{t((key + ".sub") as any)}</p>
          </div>
          {#if prefs}<input type="checkbox" checked={prefs[k as keyof AppSettings]} onchange={() => flip(k as keyof AppSettings)} aria-label={t(key as any)} />
          {:else}<span class="text-copy-13 text-gray-900">{tr("Unavailable")}</span>{/if}
        </div>
      {/each}
      <div class="row justify-between gap-4"><span class="text-label-13">{app.mode === "simple" ? tr("Icon near the clock") : tr("Tray icon")}</span><span class="text-right text-copy-13 text-gray-900">{app.mode === "simple" ? tr("A coloured dot shows how things are going") : tr("Green, amber, orange; grey when unreachable")}</span></div>
    </div>
    <p class="mt-2 px-1 text-copy-13 text-gray-900">{tr("These only control pop-ups from this app. ARGUS-INSTINCT keeps watching either way.")}</p>
  </section>
  {/if}

  {@render group(tr("Connection"), [
    [tr("Service"), app.daemon === "live" ? tr("Answering") : app.daemon === "down" ? tr("Not answering") : tr("Connecting")],
    [app.mode === "simple" ? tr("Who can reach it") : tr("Address"), app.mode === "simple" ? tr("Only this computer. Nobody else on your network can.") : tr("127.0.0.1 only (port 8787, or JARVIS_DESKTOP_PORT)")],
    [tr("Closing the window"), app.mode === "simple" ? tr("ARGUS-INSTINCT keeps watching from the icon near the clock") : tr("Hides it to the tray; monitoring continues")],
  ])}
  {@render group(tr("Shortcuts"), [[tr("Search"), "Ctrl K  /  /"], [tr("Close a panel"), "Esc"]])}
</div>
