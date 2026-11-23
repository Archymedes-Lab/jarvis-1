<script lang="ts">
  import { ToggleGroup } from "bits-ui";
  type Item = { value: string; label: string; count?: number; tone?: string };
  let { items, value = $bindable(""), label }: { items: Item[]; value?: string; label: string } = $props();
</script>

<!-- Single choice that can be cleared by clicking the active item again; an
     empty value means "all". -->
<ToggleGroup.Root type="single" bind:value aria-label={label} class="segmented">
  {#each items as it (it.value)}
    <ToggleGroup.Item value={it.value} class="seg-item">
      {it.label}{#if it.count !== undefined}<span class="tabular {it.tone ?? 'text-gray-700'}">{it.count}</span>{/if}
    </ToggleGroup.Item>
  {/each}
</ToggleGroup.Root>
