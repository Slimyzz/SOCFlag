// Quick manual check: node test/run-solutions.mjs [id-prefix]
import { sections } from '../content/index.js';
import { unseal } from '../assets/js/lib/seal.js';
import { resolveSpec } from '../assets/js/ui/workspace.js';
import { solutions, toolkit } from './solutions.js';
const only = process.argv[2] ?? '';
for (const c of sections.flatMap((s) => s.challenges)) {
  if (!c.id.startsWith(only)) continue;
  const flag = c.flag === 'COMPUTE' ? '' : unseal(c.id, c.flag);
  const out = solutions[c.id]?.(toolkit(resolveSpec(c.workspace, flag)));
  console.log(c.id.padEnd(26), c.flag === 'COMPUTE' ? `computed ${out}` : String(out).toLowerCase().includes(flag.toLowerCase()) ? 'ok' : `MISSING in ${JSON.stringify(out).slice(0, 120)}`);
}
