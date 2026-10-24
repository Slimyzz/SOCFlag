// A small SIEM search screen: query bar, event timeline, field summary and
// results. Data is generated per lab, so every search runs locally.
import { h, fill } from '../core/dom.js';
import { runQuery, summarise, QueryError, COMMAND_HELP } from '../lib/query.js';

export function formatTime(ms) {
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');
}

function cell(value, column, timeColumns = new Set(['_time'])) {
  if (timeColumns.has(column) && typeof value === 'number') return formatTime(value);
  if (Array.isArray(value)) return value.join('\n');
  if (value === undefined || value === null) return '';
  return String(value);
}

// A bar chart of how many events fall in each slice of the time range.
function histogram(rows) {
  if (rows.length < 2) return null;
  const times = rows.map((r) => r._time).filter(Number.isFinite);
  const min = Math.min(...times), max = Math.max(...times);
  if (max === min) return null;
  const buckets = 48;
  const counts = new Array(buckets).fill(0);
  for (const t of times) counts[Math.min(buckets - 1, Math.floor(((t - min) / (max - min)) * buckets))]++;
  const peak = Math.max(...counts);
  const bars = counts.map((c, i) => `<rect x="${i * 10 + 1}" y="${40 - (c / peak) * 38}" width="8" height="${(c / peak) * 38}"><title>${c} events</title></rect>`).join('');
  return h('figure', { class: 'siem-chart' },
    h('div', { html: `<svg viewBox="0 0 480 40" preserveAspectRatio="none" role="img" aria-label="Events over time, peak ${peak} per slice">${bars}</svg>` }),
    h('figcaption', {}, h('span', {}, formatTime(min)), h('span', {}, formatTime(max))));
}

export function mountSiem(host, spec, report) {
  const events = spec.events;
  const history = [];
  let historyIndex = 0;
  const input = h('input', { class: 'field siem-input', type: 'text', value: spec.start ?? 'index=*', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Search query' });
  const form = h('form', { class: 'siem-bar' }, input, h('button', { class: 'btn primary small', type: 'submit' }, 'Search'));
  const status = h('p', { class: 'siem-status', 'aria-live': 'polite' });
  const results = h('div', { class: 'siem-results' });
  const fieldsBox = h('details', { class: 'siem-fields' }, h('summary', {}, 'Fields in these results'));
  const sources = [...new Set(events.map((e) => e.index))].map((index) => `${index} (${events.filter((e) => e.index === index).length})`).join(', ');
  const help = h('details', { class: 'siem-help' },
    h('summary', {}, 'Query help'),
    h('div', { class: 'siem-help-body' },
      h('p', {}, 'Start with a search, then add commands after a pipe. Each command works on the output of the one before it.'),
      h('dl', {}, Object.entries(COMMAND_HELP).map(([name, text]) => [h('dt', {}, name), h('dd', {}, text)])),
      spec.examples?.length ? [h('p', { style: 'margin-top:.75rem;font-weight:700' }, 'Try:'), h('ul', {}, spec.examples.map((q) => h('li', {}, h('button', { class: 'linklike mono', type: 'button', onclick: () => { input.value = q; run(); } }, q))))] : null));

  fill(host, h('div', { class: 'siem' },
    form,
    h('p', { class: 'siem-sources' }, `Data: ${sources}. All times are UTC.`),
    help, status, fieldsBox, results));

  function addFilter(field, value) {
    const term = `${field}=${/[\s"=]/.test(value) || value === '' ? `"${value.replace(/"/g, '\\"')}"` : value}`;
    const [search, ...rest] = input.value.split('|');
    input.value = [`${search.trim()} ${term}`.trim(), ...rest.map((r) => r.trim())].join(' | ');
    run();
  }

  function renderFields(rows) {
    const summary = summarise(rows.slice(0, 2000)).filter((f) => f.field !== 'index' || f.distinct > 1);
    fill(fieldsBox, h('summary', {}, `Fields in these results (${summary.length})`),
      h('div', { class: 'siem-field-list' }, summary.map((f) => h('div', { class: 'siem-field' },
        h('strong', {}, f.field), h('span', { class: 'muted' }, ` ${f.distinct} value${f.distinct === 1 ? '' : 's'}`),
        h('ul', {}, f.top.map(([value, count]) => h('li', {},
          h('button', { class: 'linklike', type: 'button', title: `Add ${f.field}=${value} to the search`, onclick: () => addFilter(f.field, value) }, value || '(empty)'),
          h('span', { class: 'muted' }, ` ${count}`))))))));
  }

  function renderEvents(rows) {
    const shown = rows.slice(0, 150);
    fill(results, 
      histogram(rows),
      h('ol', { class: 'siem-events' }, shown.map((row) => {
        const fields = Object.entries(row).filter(([k]) => !['_raw', '_time'].includes(k));
        return h('li', {},
          h('time', {}, formatTime(row._time)),
          h('details', {}, h('summary', { class: 'mono' }, row._raw ?? JSON.stringify(row)),
            h('table', {}, fields.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', {}, h('button', { class: 'linklike', type: 'button', onclick: () => addFilter(k, String(v)) }, cell(v, k))))))));
      })),
      rows.length > shown.length ? h('p', { class: 'muted small' }, `Showing the newest ${shown.length} of ${rows.length}. Narrow the search or use stats to see the rest.`) : null);
  }

  function renderTable(rows, columns, timeColumns) {
    const shown = rows.slice(0, 500);
    fill(results, h('div', { class: 'siem-table-wrap' }, h('table', { class: 'siem-table' },
      h('thead', {}, h('tr', {}, columns.map((c) => h('th', {}, c)))),
      h('tbody', {}, shown.map((row) => h('tr', {}, columns.map((c) => h('td', {}, cell(row[c], c, timeColumns)))))))),
      rows.length > shown.length ? h('p', { class: 'muted small' }, `Showing ${shown.length} of ${rows.length} rows.`) : null);
  }

  function run() {
    const query = input.value.trim();
    if (!query) return;
    if (history[history.length - 1] !== query) history.push(query);
    historyIndex = history.length;
    const started = performance.now();
    try {
      const { rows, columns, timeColumns } = runQuery(events, query);
      const ms = Math.max(1, Math.round(performance.now() - started));
      status.className = 'siem-status';
      const noun = columns ? (rows.length === 1 ? 'row' : 'rows') : (rows.length === 1 ? 'event' : 'events');
      status.textContent = `${rows.length.toLocaleString()} ${noun} in ${ms} ms`;
      if (columns) {
        renderTable(rows, columns.length ? columns : Object.keys(rows[0] ?? {}), timeColumns);
        fieldsBox.hidden = true;
      } else {
        renderEvents(rows);
        renderFields(rows);
        fieldsBox.hidden = false;
      }
      report({ type: 'query', query, count: rows.length, columns, rows: rows.slice(0, 50) });
    } catch (error) {
      if (!(error instanceof QueryError)) throw error;
      status.className = 'siem-status error';
      status.textContent = error.message;
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    run();
  });
  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowUp' && history.length) {
      event.preventDefault();
      historyIndex = Math.max(0, historyIndex - 1);
      input.value = history[historyIndex];
    } else if (event.key === 'ArrowDown' && history.length) {
      event.preventDefault();
      historyIndex = Math.min(history.length, historyIndex + 1);
      input.value = history[historyIndex] ?? '';
    }
  });
  run();
  return { input, run: (q) => { input.value = q; run(); } };
}
