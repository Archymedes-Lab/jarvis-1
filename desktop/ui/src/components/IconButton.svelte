<script lang="ts">
  import { Tooltip } from "bits-ui";
  import type { Snippet } from "svelte";
  let { label, onclick, disabled = false, children }: { label: string; onclick: () => void; disabled?: boolean; children: Snippet } = $props();
</script>

<Tooltip.Root delayDuration={400}>
  <Tooltip.Trigger class="btn btn-ghost w-8 justify-center px-0" aria-label={label} {onclick} {disabled}>
    {@render children()}
  </Tooltip.Trigger>
  <Tooltip.Portal>
    <Tooltip.Content class="tooltip" sideOffset={6}>{label}</Tooltip.Content>
  </Tooltip.Portal>
</Tooltip.Root>
