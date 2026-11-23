<script lang="ts">
  import { sevWord } from "../lib/words";
  let { severity }: { severity: string } = $props();
  const known = ["critical", "high", "medium", "low", "ok"];
</script>
<span class="pill pill-{known.includes(severity) ? severity : 'low'}">{sevWord(severity)}</span>
