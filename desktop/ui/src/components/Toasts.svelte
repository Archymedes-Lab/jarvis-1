<script lang="ts">
  /* Apple-style banners: a small frosted capsule that drops in at the top centre,
     says one thing, and leaves by itself. Hovering keeps it on screen; the small ✕
     that appears on hover dismisses it. Errors stay longer than good news. */
  import { CircleCheck, TriangleAlert, Info, X } from "@lucide/svelte";
  import { app, dismissToast, type Toast } from "../lib/store.svelte";
  import { tr } from "../lib/i18n";

  const LIFE = { ok: 3500, info: 4500, bad: 8000 } as const;

  function life(node: HTMLElement, t: Toast) {
    let left = LIFE[t.tone] + (t.detail ? 1500 : 0) + (t.action ? 3000 : 0);
    let started = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = () => { started = Date.now(); timer = setTimeout(() => dismissToast(t.id), left); };
    const hold = () => { if (timer) { clearTimeout(timer); timer = undefined; left -= Date.now() - started; left = Math.max(left, 1500); } };
    node.addEventListener("pointerenter", hold);
    node.addEventListener("pointerleave", run);
    run();
    return { destroy() { if (timer) clearTimeout(timer); node.removeEventListener("pointerenter", hold); node.removeEventListener("pointerleave", run); } };
  }
</script>

<div class="pointer-events-none fixed inset-x-0 top-3 z-50 flex flex-col items-center gap-2 px-4" aria-live="polite">
  {#each app.toasts as t (t.id)}
    <div use:life={t} role={t.tone === "bad" ? "alert" : "status"} class="banner group pointer-events-auto">
      <span class="banner-icon {t.tone}">
        {#if t.tone === "ok"}<CircleCheck size={20} strokeWidth={2.2} />
        {:else if t.tone === "bad"}<TriangleAlert size={20} strokeWidth={2.2} />
        {:else}<Info size={20} strokeWidth={2.2} />{/if}
      </span>
      <span class="min-w-0 flex-1">
        <span class="block truncate text-label-13 text-gray-1000">{t.text}</span>
        {#if t.detail}<span class="mt-0.5 block text-copy-13 text-gray-900">{t.detail}</span>{/if}
      </span>
      {#if t.action}
        <button class="banner-action" onclick={() => { t.action?.run(); dismissToast(t.id); }}>{t.action.label}</button>
      {/if}
      <button class="banner-close" aria-label={tr("Close")} onclick={() => dismissToast(t.id)}><X size={12} strokeWidth={2.6} /></button>
    </div>
  {/each}
</div>

<style>
  .banner {
    position: relative;
    display: flex; align-items: center; gap: 12px;
    width: min(380px, 100%);
    padding: 10px 14px 10px 12px;
    border-radius: 20px;
    background: var(--material);
    -webkit-backdrop-filter: saturate(180%) blur(24px);
    backdrop-filter: saturate(180%) blur(24px);
    box-shadow: var(--shadow-pop);
    animation: drop .42s cubic-bezier(.2, 1.1, .3, 1);
  }
  .banner-icon { display: grid; place-items: center; flex: none; width: 28px; height: 28px; border-radius: 9999px; }
  .banner-icon.ok { color: var(--green-700); }
  .banner-icon.bad { color: var(--amber-700); }
  .banner-icon.info { color: var(--blue-700); }
  .banner-action {
    flex: none; height: 28px; padding: 0 12px; border-radius: 9999px;
    font-size: 13px; font-weight: 600; color: var(--blue-900);
    background: var(--blue-100); cursor: default; transition: filter .1s;
  }
  .banner-action:hover { filter: brightness(.96); }
  .banner-close {
    position: absolute; top: -6px; left: -6px; display: grid; place-items: center;
    width: 18px; height: 18px; border-radius: 9999px; color: var(--gray-900);
    background: var(--material); box-shadow: var(--shadow-card); cursor: default;
    opacity: 0; transition: opacity .12s;
    -webkit-backdrop-filter: blur(12px); backdrop-filter: blur(12px);
  }
  .banner:hover .banner-close, .banner-close:focus-visible { opacity: 1; }
  @keyframes drop { from { opacity: 0; transform: translateY(-16px) scale(.96); } }
</style>
