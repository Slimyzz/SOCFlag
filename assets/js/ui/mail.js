// A read-only mailbox for phishing analysis. Messages are never rendered as
// HTML: the body is shown as text with every link's real destination, which
// is how an analyst should look at a suspicious email anyway.
import { h } from '../core/dom.js';
import { parseMessage, htmlToSafeText } from '../lib/mime.js';
import { sha256 } from '../lib/hash.js';
import { describeBytes } from '../shell/commands.js';
import { toHex, isPrintable, looksBinary } from '../lib/bytes.js';

// Shows an attachment as text without ever running or rendering it.
// Unprintable bytes become dots, the way a hex viewer shows them.
function attachmentText(bytes) {
  const limit = 20000;
  const shown = Array.from(bytes.subarray(0, limit), (b) => (isPrintable(b) || b === 10 || b === 9 ? String.fromCharCode(b) : b === 13 ? '' : '.')).join('');
  return bytes.length > limit ? `${shown}\n\n(First ${limit.toLocaleString()} of ${bytes.length.toLocaleString()} bytes shown.)` : shown;
}

function hexPreview(bytes) {
  const rows = [];
  for (let i = 0; i < Math.min(bytes.length, 256); i += 16) {
    const row = bytes.subarray(i, i + 16);
    rows.push(`${i.toString(16).padStart(8, '0')}  ${toHex(row, ' ').padEnd(47)}  ${Array.from(row, (b) => (isPrintable(b) ? String.fromCharCode(b) : '.')).join('')}`);
  }
  return rows.join('\n');
}

export function mountMail(host, spec, report) {
  const messages = spec.messages.map((raw, index) => ({ index, raw, ...parseMessage(raw) }));
  const list = h('ul', { class: 'mail-list', role: 'listbox', 'aria-label': 'Messages' });
  const view = h('div', { class: 'mail-view' });
  host.replaceChildren(h('div', { class: 'mail' }, list, view));

  const tabs = ['Message', 'Headers', 'Source'];
  let current = null;
  let tab = 'Message';

  function open(message) {
    current = message;
    list.querySelectorAll('[role="option"]').forEach((el, i) => el.setAttribute('aria-selected', String(i === message.index)));
    render();
    report({ type: 'open-mail', index: message.index, subject: message.subject });
  }

  function render() {
    const m = current;
    const tabBar = h('div', { role: 'tablist', class: 'mail-tabs' }, tabs.map((name) => h('button', {
      role: 'tab', type: 'button', 'aria-selected': String(name === tab),
      onclick: () => {
        tab = name;
        render();
        report({ type: 'mail-tab', tab: name, index: m.index });
      }
    }, name)));
    let body;
    if (tab === 'Message') {
      const content = m.html ? htmlToSafeText(m.html) : m.text ?? '(no text body)';
      body = h('div', {},
        h('pre', { class: 'mail-body' }, content),
        m.attachments.length ? h('div', { class: 'mail-attachments' }, h('h3', {}, `Attachments (${m.attachments.length})`),
          m.attachments.map((a) => h('details', {},
            h('summary', {}, `${a.filename}  (${a.bytes.length.toLocaleString()} bytes)`),
            h('dl', {},
              h('dt', {}, 'Declared type'), h('dd', {}, a.type),
              h('dt', {}, 'Actual content'), h('dd', {}, describeBytes(a.bytes)),
              h('dt', {}, 'SHA-256'), h('dd', { class: 'mono' }, sha256(a.bytes))),
            h('pre', { class: 'mail-hex' }, hexPreview(a.bytes)),
            a.bytes.length > 256 || !looksBinary(a.bytes) ? h('details', { class: 'mail-attachment-text', ontoggle: (e) => { if (e.target.open) report({ type: 'attachment-text', index: m.index, filename: a.filename }); } },
              h('summary', {}, 'View contents as text'),
              h('pre', { class: 'mail-source' }, attachmentText(a.bytes))) : null))) : null);
    } else if (tab === 'Headers') {
      body = h('table', { class: 'mail-headers' }, m.headers.map((hd) => h('tr', { class: /^(received|authentication-results|return-path|reply-to|received-spf|dkim-signature|x-originating-ip)$/i.test(hd.name) ? 'key' : '' }, h('th', {}, hd.name), h('td', {}, hd.value))));
    } else {
      body = h('pre', { class: 'mail-source' }, m.raw);
    }
    view.replaceChildren(
      h('div', { class: 'mail-summary' },
        h('h3', {}, m.subject || '(no subject)'),
        h('dl', {}, h('dt', {}, 'From'), h('dd', {}, m.from), h('dt', {}, 'To'), h('dd', {}, m.to), h('dt', {}, 'Date'), h('dd', {}, m.date))),
      tabBar, h('div', { class: 'mail-pane', role: 'tabpanel' }, body));
  }

  list.replaceChildren(...messages.map((m) => h('li', {
    role: 'option', tabindex: '0', 'aria-selected': 'false',
    onclick: () => open(m),
    onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(m); } }
  }, h('strong', {}, m.from.replace(/<.*>/, '').replace(/"/g, '').trim() || m.from), h('span', {}, m.subject))));
  open(messages[spec.open ?? 0]);
  return { open: (i) => open(messages[i]) };
}
