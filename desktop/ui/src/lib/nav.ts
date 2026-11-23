import LayoutGrid from "@lucide/svelte/icons/layout-grid";
import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
import Activity from "@lucide/svelte/icons/activity";
import CircleCheck from "@lucide/svelte/icons/circle-check";
import MessageSquare from "@lucide/svelte/icons/message-square";
import CreditCard from "@lucide/svelte/icons/credit-card";
import Settings from "@lucide/svelte/icons/settings";
import MapPin from "@lucide/svelte/icons/map-pin";
import Grid3x3 from "@lucide/svelte/icons/grid-3x3";
import Globe from "@lucide/svelte/icons/globe";
import Cpu from "@lucide/svelte/icons/cpu";
import Smartphone from "@lucide/svelte/icons/smartphone";
import KeyRound from "@lucide/svelte/icons/key-round";
import type { View } from "./store.svelte";

/** Views Simple leaves out of the sidebar: technical detail, or not about this computer.
 *  They stay one switch away (Settings, Detail level), and links can still open them. */
export const EXPERT_ONLY: View[] = ["collectors", "world"];

export type NavGroup = "main" | "explore" | "bottom";

export const NAV: { view: View; label: string; icon: typeof LayoutGrid; group: NavGroup }[] = [
  { view: "overview", label: "Overview", icon: LayoutGrid, group: "main" },
  { view: "findings", label: "Findings", icon: TriangleAlert, group: "main" },
  { view: "collectors", label: "Collectors", icon: Activity, group: "main" },
  { view: "review", label: "Review", icon: CircleCheck, group: "main" },
  { view: "assistant", label: "Assistant", icon: MessageSquare, group: "main" },
  { view: "geo", label: "GeoSecurity", icon: MapPin, group: "explore" },
  { view: "coverage", label: "Coverage", icon: Grid3x3, group: "explore" },
  { view: "world", label: "World", icon: Globe, group: "explore" },
  { view: "procs", label: "Processes", icon: Cpu, group: "explore" },
  { view: "phone", label: "Phone", icon: Smartphone, group: "bottom" },
  { view: "pricing", label: "Pricing", icon: CreditCard, group: "bottom" },
  { view: "licence", label: "Licence", icon: KeyRound, group: "bottom" },
  { view: "settings", label: "Settings", icon: Settings, group: "bottom" },
];
