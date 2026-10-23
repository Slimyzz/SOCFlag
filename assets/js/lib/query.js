// HQL, the HiddenWell query language. It borrows the shape of the search
// languages used in real SIEMs (Splunk SPL in particular): a search
// expression, then a pipeline of commands.
//
//   index=auth action=failure user=adm* | stats count, dc(user) as users by src_ip | sort -count | head 5
//
// Events are plain objects. `_time` is milliseconds since the epoch and
// `_raw` is the original log line. Field names are case sensitive, values
// in searches are not, which matches how most SIEMs behave.

export class QueryError extends Error {}

// ------------------------------------------------------------ tokens

// In search mode * is a wildcard inside a word. In eval mode it multiplies.
function tokenize(source, { math = false } = {}) {
  const ops = math ? ['!=', '>=', '<=', '==', '=', '>', '<', '(', ')', ',', '+', '-', '*', '/'] : ['!=', '>=', '<=', '==', '=', '>', '<', '(', ')', ','];
  const word = math ? /^[^\s"'=!<>|(),+\-*/]+/ : /^[^\s"'=!<>|(),]+/;
  const tokens = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === '"' || ch === "'") {
      let value = '';
      let j = i + 1;
      while (j < source.length && source[j] !== ch) {
        if (source[j] === '\\' && j + 1 < source.length) { value += source[j + 1]; j += 2; continue; }
        value += source[j++];
      }
      if (j >= source.length) throw new QueryError(`A quoted value starting at character ${i + 1} is never closed.`);
      tokens.push({ type: 'str', value });
      i = j + 1;
      continue;
    }
    const op = ops.find((o) => source.startsWith(o, i));
    if (op) {
      tokens.push({ type: 'op', value: op });
      i += op.length;
      continue;
    }
    const match = word.exec(source.slice(i));
    if (!match) throw new QueryError(`Unexpected character "${ch}".`);
    tokens.push({ type: 'word', value: match[0] });
    i += match[0].length;
  }
  return tokens;
}

// Splits on top-level pipes, ignoring pipes inside quotes.
function splitPipes(source) {
  const parts = [];
  let current = '', quote = null;
  for (const ch of source) {
    if (quote) {
      if (ch === quote) quote = null;
      current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
    } else if (ch === '|') {
      parts.push(current.trim());
      current = '';
    } else current += ch;
  }
  parts.push(current.trim());
  return parts;
}

// ------------------------------------------------------------ search expressions

function wildcard(pattern) {
  const source = String(pattern).split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${source}$`, 'i');
}

function compare(a, op, b) {
  const na = Number(a), nb = Number(b);
  const numeric = a !== '' && b !== '' && a !== null && a !== undefined && !isNaN(na) && !isNaN(nb);
  if (op === '=' || op === '==') {
    if (numeric) return na === nb;
    return String(b).includes('*') ? wildcard(b).test(String(a ?? '')) : String(a ?? '').toLowerCase() === String(b).toLowerCase();
  }
  if (op === '!=') return !compare(a, '=', b);
  if (a === undefined || a === null) return false;
  const x = numeric ? na : String(a), y = numeric ? nb : String(b);
  return { '>': x > y, '<': x < y, '>=': x >= y, '<=': x <= y }[op];
}

class SearchParser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }
  peek() { return this.tokens[this.pos]; }
  next() { return this.tokens[this.pos++]; }
  done() { return this.pos >= this.tokens.length; }
  isWord(value) {
    const t = this.peek();
    return t && t.type === 'word' && t.value.toUpperCase() === value;
  }

  parse() {
    if (this.done()) return () => true;
    const expr = this.or();
    if (!this.done()) throw new QueryError(`Did not understand "${this.peek().value}" in the search.`);
    return expr;
  }
  or() {
    let left = this.and();
    while (this.isWord('OR')) {
      this.next();
      const right = this.and();
      const l = left;
      left = (e) => l(e) || right(e);
    }
    return left;
  }
  and() {
    let left = this.not();
    while (!this.done() && !this.isWord('OR') && !(this.peek().type === 'op' && this.peek().value === ')')) {
      if (this.isWord('AND')) this.next();
      const right = this.not();
      const l = left;
      left = (e) => l(e) && right(e);
    }
    return left;
  }
  not() {
    if (this.isWord('NOT')) {
      this.next();
      const inner = this.not();
      return (e) => !inner(e);
    }
    return this.atom();
  }
  atom() {
    const t = this.next();
    if (!t) throw new QueryError('The search ends too early.');
    if (t.type === 'op' && t.value === '(') {
      const inner = this.or();
      const close = this.next();
      if (!close || close.value !== ')') throw new QueryError('A bracket is opened but never closed.');
      return inner;
    }
    const after = this.peek();
    if (after && after.type === 'op' && ['=', '!=', '>', '<', '>=', '<=', '=='].includes(after.value)) {
      this.next();
      const valueToken = this.next();
      if (!valueToken) throw new QueryError(`"${t.value}${after.value}" needs a value after it.`);
      const field = t.value, op = after.value, value = valueToken.value;
      return (e) => {
        const actual = e[field];
        if (Array.isArray(actual)) return actual.some((item) => compare(item, op, value));
        return compare(actual, op, value);
      };
    }
    // A bare word or quoted phrase searches the raw event text.
    const needle = t.value;
    if (needle.includes('*')) {
      const re = new RegExp(needle.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*'), 'i');
      return (e) => re.test(e._raw ?? '');
    }
    const lower = needle.toLowerCase();
    return (e) => String(e._raw ?? '').toLowerCase().includes(lower);
  }
}

export function compileSearch(source) {
  return new SearchParser(tokenize(source)).parse();
}

// ------------------------------------------------------------ eval expressions

function evalExpression(source) {
  const tokens = tokenize(source, { math: true });
  let pos = 0;
  const peek = () => tokens[pos];
  const expr = () => {
    let left = term();
    while (peek() && peek().type === 'op' && (peek().value === '+' || (peek().value === '-'))) {
      const op = tokens[pos++].value;
      const right = term(), l = left;
      left = (e) => {
        const a = l(e), b = right(e);
        if (op === '+') return typeof a === 'number' && typeof b === 'number' ? a + b : `${a ?? ''}${b ?? ''}`;
        return Number(a) - Number(b);
      };
    }
    return left;
  };
  const term = () => {
    let left = factor();
    while (peek() && peek().type === 'op' && (peek().value === '*' || peek().value === '/')) {
      const op = tokens[pos++].value;
      const right = factor(), l = left;
      left = (e) => (op === '*' ? Number(l(e)) * Number(right(e)) : Number(l(e)) / Number(right(e)));
    }
    return left;
  };
  const factor = () => {
    const t = tokens[pos++];
    if (!t) throw new QueryError('An eval expression ends too early.');
    if (t.type === 'str') return () => t.value;
    if (t.type === 'op' && t.value === '(') {
      const inner = expr();
      pos++;
      return inner;
    }
    if (t.type === 'word' && /^-?\d+(\.\d+)?$/.test(t.value)) return () => Number(t.value);
    if (t.type === 'word' && peek()?.value === '(') {
      pos++;
      const args = [];
      while (peek() && peek().value !== ')') {
        args.push(expr());
        if (peek()?.value === ',') pos++;
      }
      pos++;
      const name = t.value.toLowerCase();
      const fns = {
        len: (v) => String(v ?? '').length,
        lower: (v) => String(v ?? '').toLowerCase(),
        upper: (v) => String(v ?? '').toUpperCase(),
        round: (v, n = 0) => Number(Number(v).toFixed(n)),
        tonumber: (v) => Number(v),
        abs: (v) => Math.abs(Number(v)),
        substr: (v, start, len) => String(v ?? '').substr(Number(start) - 1, len === undefined ? undefined : Number(len)),
        split_count: (v, sep) => String(v ?? '').split(sep).length,
        if: (cond, a, b) => (cond ? a : b)
      };
      if (!fns[name]) throw new QueryError(`eval does not know the function ${t.value}(). Available: ${Object.keys(fns).join(', ')}.`);
      return (e) => fns[name](...args.map((a) => a(e)));
    }
    if (t.type === 'word') return (e) => e[t.value];
    throw new QueryError(`Did not understand "${t.value}" in eval.`);
  };
  const result = expr();
  if (pos < tokens.length) throw new QueryError(`Did not understand "${tokens[pos].value}" in eval.`);
  return result;
}

// ------------------------------------------------------------ commands

function parseSpan(span) {
  const m = /^(\d+)(s|m|h|d)$/.exec(span ?? '');
  if (!m) throw new QueryError('span needs a number and a unit, like span=5m, span=1h or span=1d.');
  return Number(m[1]) * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]];
}

function splitList(text) {
  return text.split(/[\s,]+/).filter(Boolean);
}

function aggregates(spec) {
  // "count, dc(user) as users, values(action)"
  const parts = spec.match(/[a-z_]+(\([^)]*\))?(\s+as\s+[\w.]+)?/gi) ?? [];
  return parts.map((part) => {
    const m = /^([a-z_]+)(?:\(([^)]*)\))?(?:\s+as\s+([\w.]+))?$/i.exec(part.trim());
    if (!m) throw new QueryError(`Did not understand "${part}" in stats.`);
    const fn = m[1].toLowerCase();
    if (!['count', 'dc', 'sum', 'avg', 'min', 'max', 'values', 'earliest', 'latest', 'range'].includes(fn)) {
      throw new QueryError(`stats does not know ${fn}(). Use count, dc, sum, avg, min, max, values, earliest, latest or range.`);
    }
    const field = m[2]?.trim();
    const name = m[3] ?? (field ? `${fn}(${field})` : fn);
    return { fn, field, name };
  });
}

function aggregate(rows, { fn, field }) {
  const values = field ? rows.map((r) => r[field]).flat().filter((v) => v !== undefined && v !== null && v !== '') : rows;
  switch (fn) {
    case 'count': return values.length;
    case 'dc': return new Set(values.map(String)).size;
    case 'sum': return values.reduce((a, b) => a + (Number(b) || 0), 0);
    case 'avg': return values.length ? Math.round((values.reduce((a, b) => a + (Number(b) || 0), 0) / values.length) * 100) / 100 : null;
    case 'min': return values.length ? values.reduce((a, b) => (Number(a) <= Number(b) ? a : b)) : null;
    case 'max': return values.length ? values.reduce((a, b) => (Number(a) >= Number(b) ? a : b)) : null;
    case 'range': return values.length ? Math.max(...values.map(Number)) - Math.min(...values.map(Number)) : null;
    case 'values': return [...new Set(values.map(String))].sort().slice(0, 50);
    case 'earliest': return rows.length ? rows.reduce((a, b) => (a._time <= b._time ? a : b))[field] : null;
    case 'latest': return rows.length ? rows.reduce((a, b) => (a._time >= b._time ? a : b))[field] : null;
  }
}

const COMMANDS = {
  search(rows, args) {
    const test = compileSearch(args);
    return rows.filter(test);
  },
  where(rows, args) {
    const test = compileSearch(args);
    return rows.filter(test);
  },
  stats(rows, args, state) {
    const [spec, by] = args.split(/\s+by\s+/i);
    const aggs = aggregates(spec);
    const keys = by ? splitList(by) : [];
    const groups = new Map();
    for (const row of rows) {
      const key = keys.map((k) => String(row[k] ?? ''));
      if (keys.length && key.every((k) => k === '')) continue;
      const id = JSON.stringify(key);
      if (!groups.has(id)) groups.set(id, { key, rows: [] });
      groups.get(id).rows.push(row);
    }
    if (!keys.length && !groups.size) groups.set('[]', { key: [], rows: [] });
    state.columns = [...keys, ...aggs.map((a) => a.name)];
    state.table = true;
    // Times picked out by earliest, latest, min or max should still read as times.
    for (const agg of aggs) if (agg.field === '_time' && ['min', 'max', 'earliest', 'latest'].includes(agg.fn)) state.timeColumns.add(agg.name);
    return [...groups.values()].map(({ key, rows: group }) => {
      const out = {};
      keys.forEach((k, i) => {
        out[k] = k === '_time' ? Number(key[i]) : key[i];
      });
      for (const agg of aggs) out[agg.name] = aggregate(group, agg);
      return out;
    });
  },
  top(rows, args, state) {
    const limit = Number(/limit=(\d+)/.exec(args)?.[1] ?? 10);
    const fields = splitList(args.replace(/limit=\d+/, ''));
    if (!fields.length) throw new QueryError('top needs a field, like: top src_ip');
    const counts = new Map();
    for (const row of rows) {
      const key = fields.map((f) => row[f] ?? '').join('\u0000');
      if (!fields.some((f) => row[f] !== undefined)) continue;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const total = [...counts.values()].reduce((a, b) => a + b, 0) || 1;
    state.columns = [...fields, 'count', 'percent'];
    state.table = true;
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([key, count]) => {
      const out = {};
      key.split('\u0000').forEach((v, i) => { out[fields[i]] = v; });
      out.count = count;
      out.percent = Math.round((count / total) * 10000) / 100;
      return out;
    });
  },
  rare(rows, args, state) {
    const result = COMMANDS.top(rows, `${args} limit=100000`, state);
    return result.reverse().slice(0, Number(/limit=(\d+)/.exec(args)?.[1] ?? 10));
  },
  sort(rows, args) {
    const keys = splitList(args.replace(/\s*-\s+/g, ' -').replace(/\s*\+\s+/g, ' +')).filter((k) => !/^\d+$/.test(k));
    const spec = keys.map((k) => {
      if (/^(desc|asc)$/i.test(k)) return null;
      return { field: k.replace(/^[-+]/, ''), desc: k.startsWith('-') };
    }).filter(Boolean);
    if (/\bdesc\b/i.test(args) && spec.length) spec[spec.length - 1].desc = true;
    if (!spec.length) throw new QueryError('sort needs a field, like: sort -count');
    const limit = /^\s*(\d+)\s/.exec(args)?.[1];
    const sorted = [...rows].sort((a, b) => {
      for (const { field, desc } of spec) {
        const x = a[field], y = b[field];
        const nx = Number(x), ny = Number(y);
        let diff;
        if (x === undefined || x === null) diff = 1;
        else if (y === undefined || y === null) diff = -1;
        else diff = !isNaN(nx) && !isNaN(ny) && x !== '' && y !== '' ? nx - ny : String(x).localeCompare(String(y));
        if (diff) return desc ? -diff : diff;
      }
      return 0;
    });
    return limit ? sorted.slice(0, Number(limit)) : sorted;
  },
  head(rows, args) {
    return rows.slice(0, Number(args || 10));
  },
  tail(rows, args) {
    return rows.slice(-Number(args || 10));
  },
  table(rows, args, state) {
    state.columns = splitList(args);
    state.table = true;
    return rows;
  },
  fields(rows, args, state) {
    const list = splitList(args.replace(/^[-+]\s*/, ''));
    if (args.trim().startsWith('-')) {
      return rows.map((row) => Object.fromEntries(Object.entries(row).filter(([k]) => !list.includes(k))));
    }
    state.columns = list;
    state.table = true;
    return rows;
  },
  dedup(rows, args) {
    const keys = splitList(args);
    const seen = new Set();
    return rows.filter((row) => {
      const id = keys.map((k) => row[k]).join('\u0000');
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  },
  rename(rows, args, state) {
    const m = /^([\w.()]+)\s+as\s+([\w.]+)$/i.exec(args.trim());
    if (!m) throw new QueryError('rename looks like: rename src_ip as attacker');
    if (state.columns) state.columns = state.columns.map((c) => (c === m[1] ? m[2] : c));
    if (state.timeColumns.has(m[1])) state.timeColumns.add(m[2]);
    return rows.map((row) => {
      const out = { ...row, [m[2]]: row[m[1]] };
      delete out[m[1]];
      return out;
    });
  },
  eval(rows, args, state) {
    const m = /^([\w.]+)\s*=\s*(.+)$/s.exec(args.trim());
    if (!m) throw new QueryError('eval looks like: eval size_kb = bytes / 1024');
    const fn = evalExpression(m[2]);
    if (state.columns && !state.columns.includes(m[1])) state.columns.push(m[1]);
    return rows.map((row) => ({ ...row, [m[1]]: fn(row) }));
  },
  rex(rows, args) {
    const field = /field=([\w.]+)/.exec(args)?.[1] ?? '_raw';
    const pattern = /"((?:[^"\\]|\\.)*)"/.exec(args)?.[1];
    if (!pattern) throw new QueryError('rex needs a quoted regular expression with named groups, like: rex field=url "user=(?<user>\\w+)"');
    let re;
    try {
      re = new RegExp(pattern.replace(/\\"/g, '"').replace(/\(\?P</g, '(?<'));
    } catch (error) {
      throw new QueryError(`That regular expression is not valid: ${error.message}`);
    }
    return rows.map((row) => {
      const m = re.exec(String(row[field] ?? ''));
      return m?.groups ? { ...row, ...m.groups } : row;
    });
  },
  bin(rows, args) {
    const span = parseSpan(/span=(\w+)/.exec(args)?.[1]);
    const field = splitList(args.replace(/span=\w+/, ''))[0] ?? '_time';
    return rows.map((row) => ({ ...row, [field]: Math.floor(row[field] / span) * span }));
  },
  timechart(rows, args, state) {
    const span = /span=(\w+)/.exec(args)?.[1] ?? '1h';
    const rest = args.replace(/span=\w+/, '').trim() || 'count';
    const binned = COMMANDS.bin(rows, `span=${span}`);
    const [spec, by] = rest.split(/\s+by\s+/i);
    const result = COMMANDS.stats(binned, `${spec} by _time${by ? `, ${by}` : ''}`, state);
    return result.sort((a, b) => a._time - b._time);
  },
  transaction(rows, args, state) {
    // Groups events that share a field into one row with a duration.
    const field = splitList(args)[0];
    if (!field) throw new QueryError('transaction needs a field, like: transaction session_id');
    const groups = new Map();
    for (const row of [...rows].sort((a, b) => a._time - b._time)) {
      const key = row[field];
      if (key === undefined) continue;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(row);
    }
    state.columns = ['_time', field, 'eventcount', 'duration'];
    state.table = true;
    return [...groups.entries()].map(([key, group]) => ({ _time: group[0]._time, [field]: key, eventcount: group.length, duration: Math.round((group[group.length - 1]._time - group[0]._time) / 1000) }));
  }
};

export const COMMAND_HELP = {
  search: 'Filter events: field=value, field!=value, field>10, wildcards like user=adm*, free text, AND, OR, NOT and brackets.',
  where: 'Same as search, written after a pipe: | where count > 20',
  stats: 'Aggregate: | stats count, dc(user), sum(bytes), avg(x), min, max, values(f), earliest(f), latest(f) by field1, field2',
  top: 'Most common values with counts and percentages: | top src_ip limit=5',
  rare: 'Least common values: | rare user_agent',
  sort: 'Order results. A minus sign means largest first: | sort -count',
  head: 'Keep the first N results: | head 5',
  tail: 'Keep the last N results: | tail 5',
  table: 'Choose and order columns: | table _time, user, src_ip',
  fields: 'Like table. "fields - x" removes a field instead.',
  dedup: 'Keep the first event for each value: | dedup user',
  rename: 'Rename a column: | rename count as attempts',
  eval: 'Compute a new field: | eval kb = bytes / 1024 or | eval qlen = len(query)',
  rex: 'Extract fields with a regular expression: | rex field=url "id=(?<id>\\d+)"',
  bin: 'Round times into buckets before stats: | bin span=5m',
  timechart: 'Count over time: | timechart span=1h count by action',
  transaction: 'Group events that share a value and measure the duration: | transaction session'
};

export function runQuery(events, source) {
  const stages = splitPipes(source.trim());
  const state = { columns: null, table: false, timeColumns: new Set(['_time']) };
  let rows = [...events].sort((a, b) => b._time - a._time);
  const [first, ...rest] = stages;
  if (first) rows = COMMANDS.search(rows, first);
  for (const stage of rest) {
    if (!stage) throw new QueryError('There is an empty step between two pipes.');
    const [, name, args = ''] = /^(\w+)\s*([\s\S]*)$/.exec(stage) ?? [];
    const command = COMMANDS[name?.toLowerCase()];
    if (!command) throw new QueryError(`Unknown command "${name ?? stage}". Available: ${Object.keys(COMMANDS).join(', ')}.`);
    rows = command(rows, args, state);
  }
  return { rows, columns: state.table ? state.columns : null, timeColumns: state.timeColumns };
}

// Field summary for the sidebar: the most common values of each field.
export function summarise(rows, limit = 6) {
  const fields = new Map();
  for (const row of rows) {
    for (const [key, value] of Object.entries(row)) {
      if (key === '_raw' || key === '_time' || value === undefined || value === '') continue;
      if (!fields.has(key)) fields.set(key, new Map());
      const counts = fields.get(key);
      for (const v of [].concat(value)) counts.set(String(v), (counts.get(String(v)) ?? 0) + 1);
    }
  }
  return [...fields.entries()]
    .map(([field, counts]) => ({ field, distinct: counts.size, top: [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit) }))
    .sort((a, b) => a.field.localeCompare(b.field));
}
