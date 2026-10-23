// Unit tests for the in-browser shell: the commands and behaviours the
// challenges rely on.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createMachine } from '../assets/js/shell/index.js';

// A machine with a small, fixed filesystem for the tests.
function machine(extra = {}) {
  const { shell, fs } = createMachine({
    files: {
      '/home/learner/a.txt': 'alpha\nbeta\ngamma\nAlpha\n',
      '/home/learner/log/access.log': '10.0.0.1 200\n10.0.0.2 401\n10.0.0.1 401\n10.0.0.1 401\n10.0.0.3 200\n',
      '/home/learner/data/one.dat': { content: 'x'.repeat(100), mtime: Date.UTC(2026, 2, 13, 2, 0, 0) },
      '/home/learner/data/two.dat': { content: 'y'.repeat(1337), mtime: Date.UTC(2026, 2, 13, 11, 0, 0) },
      '/home/learner/secret.txt': { content: 'top secret\n', mode: 0o000 },
      ...extra
    }
  });
  return { run: (line) => shell.execute(line).chunks.map((c) => c.text).join('').replace(/\x1b\[[0-9;]*m/g, ''), fs };
}

test('cat prints file contents', () => {
  assert.match(machine().run('cat a.txt'), /alpha\nbeta\ngamma/);
});

test('grep finds matching lines; -v inverts; -i ignores case; -c counts', () => {
  const { run } = machine();
  assert.match(run('grep beta a.txt'), /beta/);
  assert.ok(!/beta/.test(run('grep -v beta a.txt')));
  assert.equal(run('grep -i alpha a.txt').trim().split('\n').length, 2);
  assert.equal(run('grep -c 401 log/access.log').trim(), '3');
});

test('grep -r searches a folder tree', () => {
  assert.match(machine().run('grep -r 401 log'), /access\.log/);
});

test('grep -f reads patterns from a file', () => {
  const { run } = machine({ '/home/learner/pats.txt': 'alpha\ngamma\n' });
  const out = run('grep -f pats.txt a.txt').trim().split('\n');
  assert.equal(out.length, 2); // alpha and gamma; "Alpha" differs in case
});

test('the count-top-talkers pipeline works', () => {
  const out = machine().run('grep 401 log/access.log | cut -d" " -f1 | sort | uniq -c | sort -rn | head -n 1');
  assert.match(out.trim(), /2 10\.0\.0\.1/);
});

test('redirection writes and appends', () => {
  const { run } = machine();
  run('echo one > out.txt; echo two >> out.txt');
  assert.equal(run('cat out.txt').trim(), 'one\ntwo');
  run('echo three > out.txt');
  assert.equal(run('cat out.txt').trim(), 'three');
});

test('find -size matches exact byte counts', () => {
  assert.match(machine().run('find /home/learner/data -type f -size 1337c'), /two\.dat/);
});

test('find -newermt selects by modification time', () => {
  const out = machine().run('find /home/learner/data -type f -newermt "2026-03-13 10:00"');
  assert.match(out, /two\.dat/);
  assert.ok(!/one\.dat/.test(out));
});

test('chmod lets an owner restore access to their own file', () => {
  const { run } = machine();
  assert.match(run('cat secret.txt'), /Permission denied|denied/i);
  run('chmod 600 secret.txt');
  assert.match(run('cat secret.txt'), /top secret/);
});

test('base64 round trips', () => {
  const { run } = machine();
  const encoded = run('echo -n hello | base64').trim();
  assert.equal(encoded, 'aGVsbG8=');
  assert.equal(run(`echo ${encoded} | base64 -d`).trim(), 'hello');
});

test('xxd -r -p and rev undo hex and reversal', () => {
  const { run } = machine();
  // "6f6c6c6568" is hex for "olleh"; reversed gives "hello".
  assert.equal(run('echo 6f6c6c6568 | xxd -r -p | rev').trim(), 'hello');
});

test('sha256sum -c verifies a manifest and reports a mismatch', () => {
  const { run } = machine();
  run('sha256sum a.txt > sums.txt');
  assert.match(run('sha256sum -c sums.txt'), /a\.txt: OK/);
  run('echo changed > a.txt');
  assert.match(run('sha256sum -c sums.txt'), /a\.txt: FAILED/);
});

test('file identifies a type by its signature, not its name', () => {
  const { run } = machine({ '/home/learner/pic.jpg': { content: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]) } });
  assert.match(run('file pic.jpg'), /PNG/);
});

test('strings pulls readable text out of binary data', () => {
  const bytes = new Uint8Array([0, 1, 2, ...[...'SECRETKEY'].map((c) => c.charCodeAt(0)), 0, 3]);
  const { run } = machine({ '/home/learner/blob.bin': { content: bytes } });
  assert.match(run('strings blob.bin'), /SECRETKEY/);
});

test('the network is unavailable in the sandbox', () => {
  assert.match(machine().run('curl http://example.com'), /no network access/i);
});
