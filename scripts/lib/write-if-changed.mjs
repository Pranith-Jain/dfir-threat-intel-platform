/** Write JSON only when its data actually changed (ignoring the generatedAt
 * stamp). Lets high-frequency sync workflows run every few minutes without
 * producing a PR (or LLM/data churn) on every quiet tick. */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function writeJsonIfChanged(file, payload) {
  const next = JSON.parse(JSON.stringify(payload));
  const stamp = next.generatedAt;
  delete next.generatedAt;
  if (existsSync(file)) {
    try {
      const prev = JSON.parse(readFileSync(file, 'utf8'));
      delete prev.generatedAt;
      if (JSON.stringify(prev) === JSON.stringify(next)) {
        console.log(`  = unchanged: ${file}`);
        return false;
      }
    } catch {
      /* corrupt/legacy file — rewrite */
    }
  }
  next.generatedAt = stamp;
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(next, null, 2)}\n`);
  return true;
}
