// Content packs served by POST /content/:pack (src/licence.ts). docs/LICENSING-ARCHITECTURE.md §7.
//
// The mechanism is real; the only pack today is a sample. The premium review report is built on the
// customer's server from its own stored observation (jarvis/response/review.py), and none of it is
// static content the server could hold back, so nothing was moved here. Candidates the owner can move
// later without sending host data anywhere: curated detection/rule-pack updates, review guidance
// text per finding kind, and intel updates. A pack is plain JSON; the answer is signed per activation.
import type { Plan } from "./env";

export type Pack = { version: number; plans: Plan[]; data: unknown };

export const PACKS: Record<string, Pack> = {
  sample: { version: 1, plans: ["server", "desktop"],
            data: { note: "Sample premium content pack: proves the server-gated delivery path end to end." } },
};
