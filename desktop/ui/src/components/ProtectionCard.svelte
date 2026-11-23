<script lang="ts">
  import { onMount } from "svelte";
  import ShieldCheck from "@lucide/svelte/icons/shield-check";
  import { api, type Protection } from "../lib/api";
  import { app, toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";

  let p = $state<Protection | null>(null);
  let busy = $state(false);
  onMount(async () => { try { p = await api.protection(); } catch { p = null; } });

  async function scan() {
    busy = true;
    try { const r = await api.scan(); toast(r.message ?? tr("Scan started"), "ok"); }
    catch (e) { toast(String((e as Error).message ?? e), "bad"); }
    finally { busy = false; }
  }
  const tone = $derived(p?.level === "on" ? "bg-green-100 text-green-900" : p?.level === "unknown" || !p ? "bg-gray-100 text-gray-900" : "bg-amber-100 text-amber-900");
  // The daemon's sentence is chosen by level; show the matching translated one.
  const summary = $derived(!p ? tr("Checking…") : p.level === "on" ? tr("Windows' virus protection is on and up to date. It blocks known viruses as they arrive.")
    : p.level === "off" ? tr("Windows' real-time virus protection is off. Turn it on in Windows Security.")
    : p.level === "stale" ? tr("Windows' virus protection is on, but its virus list is {n} days old. Run Windows Update.", { n: p.signature_age_days ?? "?" })
    : tr("Cannot read Windows antivirus right now."));
</script>

<div class="card flex items-start gap-4 p-5">
  <span class="grid size-10 shrink-0 place-items-center rounded-xl {tone}"><ShieldCheck size={20} /></span>
  <div class="min-w-0 flex-1">
    <p class="text-label-14">{app.mode === "simple" ? tr("Virus protection") : tr("Malware protection (Windows Defender)")}</p>
    <p class="mt-0.5 text-copy-13 text-gray-900">{summary}</p>
    <p class="mt-2 text-copy-13 text-gray-900">
      {app.mode === "simple"
        ? tr("ARGUS-INSTINCT detects and explains. Windows Defender blocks.")
        : tr("ARGUS-INSTINCT detects and explains. Windows Defender blocks.")}
    </p>
  </div>
  {#if p?.available}
    <button class="btn btn-sm shrink-0" disabled={busy} onclick={scan}>{app.mode === "simple" ? tr("Check for viruses") : tr("Quick scan")}</button>
  {/if}
</div>
