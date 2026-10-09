/**
 * Threat-actor knowledge base — TYPES ONLY.
 *
 * The payload lives in `public/data/actor-kb.json` and is fetched at runtime
 * by `src/pages/threatintel/ActorKb.tsx`. This module intentionally ships no
 * data: the array that used to live here (7,409 lines) had zero consumers
 * after the page moved to a runtime fetch, and it was typechecked and
 * bundled on every build for nothing.
 *
 * Regenerate the JSON payload with:
 *   node scripts/build-actor-kb.mjs
 *
 * Do NOT re-add a data export here. If a consumer needs this data, fetch
 * `/data/actor-kb.json` — do not import it as a module.
 */
export interface KbTechnique {
  id: string;
  name: string;
  tactic: string;
}
export interface KbActor {
  attackId: string;
  name: string;
  aliases: string[];
  description: string;
  url: string;
  techniques: KbTechnique[];
  software: string[];
}
