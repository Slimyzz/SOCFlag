// Proves that every challenge can be solved through its intended path: the
// solution in solutions.js, run against the challenge's own generated data,
// yields the challenge's unsealed flag.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sections } from '../content/index.js';
import { unseal, normaliseFlag } from '../assets/js/lib/seal.js';
import { resolveSpec } from '../assets/js/ui/workspace.js';
import { solutions, toolkit } from './solutions.js';

const challenges = sections.flatMap((s) => s.challenges);

test('every challenge has a solution in solutions.js', () => {
  for (const c of challenges) {
    assert.equal(typeof solutions[c.id], 'function', `no solution for ${c.id}`);
  }
});

for (const c of challenges) {
  test(`${c.id} is solvable through its intended path`, () => {
    const flag = unseal(c.id, c.flag);
    const spec = resolveSpec(c.workspace, flag);
    const out = String(solutions[c.id](toolkit(spec)));
    assert.ok(
      normaliseFlag(out).includes(normaliseFlag(flag)) || normaliseFlag(out) === normaliseFlag(flag),
      `solution for ${c.id} gave "${out}", expected to contain "${flag}"`
    );
  });
}
