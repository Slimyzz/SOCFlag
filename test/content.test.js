// Validates the shape of every section, lesson and challenge, and checks the
// flag-hiding guarantee: that no plaintext flag appears anywhere in the repo.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sections } from '../content/index.js';
import { unseal } from '../assets/js/lib/seal.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const challenges = sections.flatMap((s) => s.challenges);
const lessons = sections.flatMap((s) => s.lessons);

const BLOCK_TYPES = new Set(['heading', 'text', 'example', 'code', 'table', 'note', 'reveal', 'timeline', 'quiz', 'predict', 'answer', 'order', 'spot', 'task']);
const GRADED = new Set(['quiz', 'predict', 'answer', 'order', 'spot', 'task']);
const WORKSPACE_TYPES = new Set(['shell', 'siem', 'mail', 'packets', 'tools', 'case']);

test('sections have unique ids and the required fields', () => {
  const ids = new Set();
  for (const s of sections) {
    for (const field of ['id', 'title', 'short', 'summary', 'intro', 'outcomes', 'lessons', 'challenges']) {
      assert.ok(s[field] !== undefined, `section ${s.id} is missing ${field}`);
    }
    assert.ok(!ids.has(s.id), `duplicate section id ${s.id}`);
    ids.add(s.id);
    assert.ok(s.outcomes.length >= 3, `section ${s.id} needs at least 3 outcomes`);
  }
});

test('lesson ids are unique across the whole site', () => {
  const ids = new Set();
  for (const l of lessons) {
    assert.ok(!ids.has(l.id), `duplicate lesson id ${l.id}`);
    ids.add(l.id);
  }
});

test('challenge ids are unique across the whole site', () => {
  const ids = new Set();
  for (const c of challenges) {
    assert.ok(!ids.has(c.id), `duplicate challenge id ${c.id}`);
    ids.add(c.id);
  }
});

test('every lesson is well formed', () => {
  for (const l of lessons) {
    assert.equal(typeof l.title, 'string');
    assert.ok(l.minutes > 0, `${l.id} needs minutes`);
    assert.ok(Array.isArray(l.blocks) && l.blocks.length > 0, `${l.id} needs blocks`);
    for (const block of l.blocks) {
      assert.ok(BLOCK_TYPES.has(block.type), `${l.id} has unknown block type ${block.type}`);
      if (GRADED.has(block.type)) {
        if (block.type === 'quiz' || block.type === 'predict') {
          assert.ok(block.options.some((o) => o.correct), `${l.id} choice block has no correct option`);
        }
        if (block.type === 'answer') assert.ok(block.accept?.length, `${l.id} answer block has no accepted answers`);
        if (block.type === 'task') assert.equal(typeof block.check, 'function', `${l.id} task has no check`);
        if (block.type === 'spot') assert.ok(block.line !== undefined, `${l.id} spot has no line`);
        if (block.type === 'order') assert.ok(block.items?.length > 1, `${l.id} order needs items`);
      }
    }
    if (l.workspace) {
      const spec = typeof l.workspace === 'function' ? l.workspace('') : l.workspace;
      assert.ok(WORKSPACE_TYPES.has(spec.type), `${l.id} workspace has unknown type ${spec.type}`);
    }
  }
});

test('every challenge is well formed', () => {
  for (const c of challenges) {
    for (const field of ['title', 'difficulty', 'points', 'skills', 'brief', 'goal', 'flag', 'workspace', 'hints', 'writeup']) {
      assert.ok(c[field] !== undefined, `challenge ${c.id} is missing ${field}`);
    }
    assert.ok(['easy', 'medium', 'hard'].includes(c.difficulty), `${c.id} has bad difficulty`);
    assert.ok(c.points > 0, `${c.id} needs points`);
    assert.ok(c.hints.length >= 1, `${c.id} needs hints`);
    assert.ok(c.writeup.how && c.writeup.why, `${c.id} writeup needs how and why`);
    const spec = typeof c.workspace === 'function' ? c.workspace('test') : c.workspace;
    assert.ok(WORKSPACE_TYPES.has(spec.type), `${c.id} workspace has unknown type ${spec.type}`);
    for (const lid of c.prepare ?? []) {
      assert.ok(lessons.some((l) => l.id === lid), `${c.id} prepares with unknown lesson ${lid}`);
    }
  }
});

test('every flag is sealed and unseals to an SOC{...} value', () => {
  for (const c of challenges) {
    assert.notEqual(c.flag, 'COMPUTE', `${c.id} still has an unsealed COMPUTE flag`);
    assert.notEqual(c.flag, 'PENDING', `${c.id} still has an unsealed PENDING flag`);
    const flag = unseal(c.id, c.flag);
    assert.match(flag, /^SOC\{.+\}$/, `${c.id} does not unseal to a valid flag (got ${flag})`);
  }
});

// Walk every text file in the repo (skipping generated and author paths).
function sourceFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (['node_modules', '.git', 'test'].includes(name)) continue;
    const full = join(dir, name);
    const s = statSync(full);
    if (s.isDirectory()) sourceFiles(full, out);
    else if (/\.(js|html|css|md|json)$/.test(name)) out.push(full);
  }
  return out;
}

test('no plaintext flag appears anywhere in the shipped source', () => {
  const files = sourceFiles(ROOT).map((f) => [f, readFileSync(f, 'utf8')]);
  for (const c of challenges) {
    const flag = unseal(c.id, c.flag);
    for (const [path, body] of files) {
      assert.ok(!body.includes(flag), `plaintext flag for ${c.id} found in ${path}`);
    }
  }
});

test('the content files themselves contain no SOC{...} literal that is a real flag', () => {
  // Placeholders like SOC{host} are fine; a real flag would be one that unseals.
  const realFlags = new Set(challenges.map((c) => unseal(c.id, c.flag)));
  for (const file of readdirSync(join(ROOT, 'content')).filter((f) => f.endsWith('.js'))) {
    const body = readFileSync(join(ROOT, 'content', file), 'utf8');
    for (const match of body.matchAll(/SOC\{[^}]*\}/g)) {
      assert.ok(!realFlags.has(match[0]), `real flag ${match[0]} written in cleartext in content/${file}`);
    }
  }
});
