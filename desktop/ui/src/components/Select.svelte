<script lang="ts">
  import { Select } from "bits-ui";
  import Check from "@lucide/svelte/icons/check";
  import ChevronDown from "@lucide/svelte/icons/chevron-down";
  type Item = { value: string; label: string };
  let { items, value = $bindable(""), label, width = "w-44" }: { items: Item[]; value?: string; label: string; width?: string } = $props();
  const current = $derived(items.find((i) => i.value === value)?.label ?? items[0]?.label);
</script>

<Select.Root type="single" bind:value {items}>
  <Select.Trigger class="input flex cursor-default items-center justify-between gap-2 {width}" aria-label={label}>
    <span class="truncate">{current}</span><ChevronDown size={14} class="shrink-0 text-gray-700" />
  </Select.Trigger>
  <Select.Portal>
    <Select.Content class="popover z-50 max-h-80 min-w-[var(--bits-select-anchor-width)] overflow-auto p-1" sideOffset={6}>
      <Select.Viewport>
        {#each items as it (it.value)}
          <Select.Item value={it.value} label={it.label} class="menu-item">
            {#snippet children({ selected })}
              <span class="flex-1 truncate">{it.label}</span>{#if selected}<Check size={14} class="text-blue-900" />{/if}
            {/snippet}
          </Select.Item>
        {/each}
      </Select.Viewport>
    </Select.Content>
  </Select.Portal>
</Select.Root>
