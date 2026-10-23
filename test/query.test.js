// Unit tests for HQL, the SIEM query language.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runQuery, QueryError } from '../assets/js/lib/query.js';

const base = Date.UTC(2026, 2, 13, 0, 0, 0);
const events = [];
for (let i = 0; i < 100; i++) {
  events.push({
    _time: base + i * 60000,
    index: 'auth',
    user: ['admin', 'priya', 'tom', 'root'][i % 4],
    src_ip: i % 5 === 0 ? '203.0.113.9' : `10.0.0.${i % 7}`,
    action: i % 3 === 0 ? 'failure' : 'success',
    bytes: (i % 10) * 100,
    _raw: `event ${i} user=${['admin', 'priya', 'tom', 'root'][i % 4]}`
  });
}

const rows = (q) => runQuery(events, q).rows;

test('a bare search returns all events of an index', () => {
  assert.equal(rows('index=auth').length, 100);
});

test('field equality and inequality filter', () => {
  assert.ok(rows('index=auth action=failure').every((r) => r.action === 'failure'));
  assert.ok(rows('index=auth action!=failure').every((r) => r.action !== 'failure'));
});

test('wildcards match inside a value', () => {
  assert.ok(rows('index=auth user=adm*').every((r) => r.user === 'admin'));
});

test('numeric comparisons work', () => {
  assert.ok(rows('index=auth bytes>500').every((r) => r.bytes > 500));
});

test('AND, OR, NOT and brackets combine conditions', () => {
  assert.ok(rows('index=auth (user=tom OR user=priya) action=success').every((r) => ['tom', 'priya'].includes(r.user) && r.action === 'success'));
  assert.ok(rows('index=auth NOT src_ip=10.*').every((r) => !r.src_ip.startsWith('10.')));
});

test('free text searches the raw event', () => {
  assert.ok(rows('index=auth "user=root"').every((r) => r._raw.includes('user=root')));
});

test('stats count by groups and counts', () => {
  const r = runQuery(events, 'index=auth | stats count by user');
  assert.equal(r.columns.join(','), 'user,count');
  assert.equal(r.rows.reduce((a, b) => a + b.count, 0), 100);
});

test('stats dc counts distinct values', () => {
  const r = rows('index=auth | stats dc(user) as users');
  assert.equal(r[0].users, 4);
});

test('top returns the most common values with counts', () => {
  const r = rows('index=auth | top user limit=2');
  assert.equal(r.length, 2);
  assert.ok(r[0].count >= r[1].count);
});

test('sort with a minus sign orders largest first', () => {
  const r = rows('index=auth | stats count by src_ip | sort -count');
  for (let i = 1; i < r.length; i++) assert.ok(r[i - 1].count >= r[i].count);
});

test('where filters aggregated rows', () => {
  const r = rows('index=auth | stats count by src_ip | where count > 15');
  assert.ok(r.every((row) => row.count > 15));
});

test('eval computes a new field', () => {
  const r = rows('index=auth | eval kb = bytes / 1024 | head 1');
  assert.ok('kb' in r[0]);
});

test('rex extracts a named group', () => {
  const r = rows('index=auth | rex "user=(?<who>\\w+)" | stats count by who');
  assert.ok(r.some((row) => row.who === 'root'));
});

test('dedup keeps one row per value', () => {
  assert.equal(rows('index=auth | dedup user').length, 4);
});

test('timechart buckets over time', () => {
  const r = runQuery(events, 'index=auth | timechart span=30m count');
  assert.ok(r.rows.length > 1);
});

test('an unknown command is a QueryError', () => {
  assert.throws(() => runQuery(events, 'index=auth | nonsense'), QueryError);
});

test('an unclosed quote is a QueryError', () => {
  assert.throws(() => runQuery(events, 'index=auth "open'), QueryError);
});
