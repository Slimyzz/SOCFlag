// A Wireshark-style capture viewer: packet list, display filters, packet
// details with a payload hex dump, Follow Stream and a conversations table.
import { h } from '../core/dom.js';
import { latin1, toHex, isPrintable } from '../lib/bytes.js';

const PROTOCOLS = ['tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'tls', 'ftp', 'smtp', 'telnet', 'ssh', 'dhcp', 'smb'];

export class FilterError extends Error {}

function fieldValue(p, field) {
  switch (field) {
    case 'ip.src': return [p.src];
    case 'ip.dst': return [p.dst];
    case 'ip.addr': return [p.src, p.dst];
    case 'tcp.port': return p.proto === 'TCP' ? [p.sport, p.dport] : [];
    case 'udp.port': return p.proto === 'UDP' ? [p.sport, p.dport] : [];
    case 'tcp.srcport': case 'udp.srcport': return [p.sport];
    case 'tcp.dstport': case 'udp.dstport': return [p.dport];
    case 'port': return [p.sport, p.dport];
    case 'frame.len': return [p.len];
    case 'frame.number': return [p.no];
    case 'tcp.flags.syn': return [/SYN/.test(p.flags ?? '') ? 1 : 0];
    case 'tcp.flags.ack': return [/ACK/.test(p.flags ?? '') ? 1 : 0];
    case 'tcp.flags.reset': return [/RST/.test(p.flags ?? '') ? 1 : 0];
    case 'tcp.flags.fin': return [/FIN/.test(p.flags ?? '') ? 1 : 0];
    case 'dns.qry.name': return p.dns ? [p.dns.qname] : [];
    case 'dns.flags.response': return p.dns ? [p.dns.response ? 1 : 0] : [];
    case 'http.request.method': return p.http?.method ? [p.http.method] : [];
    case 'http.host': return p.http?.host ? [p.http.host] : [];
    case 'http.request.uri': return p.http?.uri ? [p.http.uri] : [];
    case 'http.response.code': return p.http?.status ? [p.http.status] : [];
    case 'http.user_agent': return p.http?.ua ? [p.http.ua] : [];
    case 'tls.handshake.extensions_server_name': return p.tls?.sni ? [p.tls.sni] : [];
    default: throw new FilterError(`Unknown field "${field}". Try ip.addr, ip.src, ip.dst, tcp.port, udp.port, dns.qry.name, http.host or frame.len.`);
  }
}

function ipNumber(ip) {
  const parts = ip.split('.').map(Number);
  return parts.length === 4 && parts.every((n) => n >= 0 && n <= 255) ? ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0 : null;
}

function inRange(ip, base, bits) {
  const a = ipNumber(ip), b = ipNumber(base);
  if (a === null || b === null || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function tokenize(source) {
  const out = [];
  const re = /\s*(&&|\|\||==|!=|>=|<=|>|<|!|\(|\)|"[^"]*"|[\w.:/-]+)/y;
  let m;
  let index = 0;
  while (index < source.length) {
    re.lastIndex = index;
    m = re.exec(source);
    if (!m) {
      if (/^\s*$/.test(source.slice(index))) break;
      throw new FilterError(`Did not understand "${source.slice(index).trim()}".`);
    }
    out.push(m[1]);
    index = re.lastIndex;
  }
  return out;
}

export function compileFilter(source) {
  const tokens = tokenize(source.trim());
  let pos = 0;
  const peek = () => tokens[pos]?.toLowerCase();
  const or = () => {
    let left = and();
    while (peek() === '||' || peek() === 'or') {
      pos++;
      const right = and(), l = left;
      left = (p) => l(p) || right(p);
    }
    return left;
  };
  const and = () => {
    let left = not();
    while (peek() === '&&' || peek() === 'and') {
      pos++;
      const right = not(), l = left;
      left = (p) => l(p) && right(p);
    }
    return left;
  };
  const not = () => {
    if (peek() === '!' || peek() === 'not') {
      pos++;
      const inner = not();
      return (p) => !inner(p);
    }
    return atom();
  };
  const atom = () => {
    const t = tokens[pos++];
    if (t === undefined) throw new FilterError('The filter ends too early.');
    if (t === '(') {
      const inner = or();
      if (tokens[pos++] !== ')') throw new FilterError('A bracket is opened but never closed.');
      return inner;
    }
    const lower = t.toLowerCase();
    if (lower === 'frame' && peek() === 'contains') {
      pos++;
      const needle = (tokens[pos++] ?? '').replace(/^"|"$/g, '').toLowerCase();
      return (p) => `${p.info} ${p.payload ?? ''}`.toLowerCase().includes(needle);
    }
    if (PROTOCOLS.includes(lower) && !['==', '!=', '>', '<', '>=', '<=', 'contains'].includes(peek())) {
      return (p) => p.proto.toLowerCase() === lower || (p.app ?? '').toLowerCase() === lower;
    }
    const op = tokens[pos++];
    if (op?.toLowerCase() === 'contains') {
      const needle = (tokens[pos++] ?? '').replace(/^"|"$/g, '').toLowerCase();
      fieldValue({ proto: 'TCP' }, lower);
      return (p) => fieldValue(p, lower).some((v) => String(v ?? '').toLowerCase().includes(needle));
    }
    if (!['==', '!=', '>', '<', '>=', '<='].includes(op)) throw new FilterError(`Expected ==, !=, >, < or contains after "${t}".`);
    const raw = tokens[pos++];
    if (raw === undefined) throw new FilterError(`"${t} ${op}" needs a value.`);
    const value = raw.replace(/^"|"$/g, '');
    fieldValue({ proto: 'TCP', src: '', dst: '' }, lower);
    // Like Wireshark, an address can be a whole range: ip.src == 10.0.0.0/8
    const range = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(value);
    const equals = range ? (v) => inRange(String(v), range[1], Number(range[2])) : (v) => String(v).toLowerCase() === value.toLowerCase();
    return (p) => {
      const values = fieldValue(p, lower);
      if (op === '!=') return values.length > 0 && values.every((v) => !equals(v));
      return values.some((v) => {
        if (op === '==') return equals(v);
        const a = Number(v), b = Number(value);
        return { '>': a > b, '<': a < b, '>=': a >= b, '<=': a <= b }[op];
      });
    };
  };
  if (!tokens.length) return () => true;
  const fn = or();
  if (pos < tokens.length) throw new FilterError(`Did not understand "${tokens[pos]}".`);
  return fn;
}

function streamKey(p) {
  const a = `${p.src}:${p.sport}`, b = `${p.dst}:${p.dport}`;
  return `${p.proto}|${[a, b].sort().join('|')}`;
}

function hexDump(bytes) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.subarray(i, i + 16);
    rows.push(`${i.toString(16).padStart(4, '0')}  ${toHex(row, ' ').padEnd(47)}  ${Array.from(row, (b) => (isPrintable(b) ? String.fromCharCode(b) : '.')).join('')}`);
  }
  return rows.join('\n') || '(no payload)';
}

export function mountPackets(host, spec, report) {
  const packets = spec.packets.map((p, i) => ({ no: i + 1, len: p.len ?? 54 + (p.payload?.length ?? 0), ...p }));
  const filterInput = h('input', { class: 'field', type: 'text', placeholder: 'Display filter, e.g. dns or ip.addr == 10.0.0.5 && tcp.port == 80', spellcheck: 'false', 'aria-label': 'Display filter' });
  const filterForm = h('form', { class: 'pcap-filter row' }, h('div', { style: 'flex:1' }, filterInput), h('button', { class: 'btn small', type: 'submit' }, 'Apply'), h('button', { class: 'btn small', type: 'button', onclick: () => { filterInput.value = ''; apply(); } }, 'Clear'));
  const status = h('p', { class: 'pcap-status', 'aria-live': 'polite' });
  const tbody = h('tbody');
  const list = h('div', { class: 'pcap-list' }, h('table', {}, h('thead', {}, h('tr', {}, ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].map((c) => h('th', {}, c)))), tbody));
  const detail = h('div', { class: 'pcap-detail' });
  const views = h('div', { class: 'pcap-tools row' },
    h('button', { class: 'btn small', type: 'button', onclick: () => follow() }, 'Follow stream'),
    h('button', { class: 'btn small', type: 'button', onclick: () => conversations() }, 'Conversations'),
    h('button', { class: 'btn small', type: 'button', onclick: () => showList() }, 'Packet list'));
  const main = h('div');
  host.replaceChildren(h('div', { class: 'pcap' }, filterForm, status, views, main));

  let visible = packets;
  let selected = packets[0];

  const showList = () => {
    main.replaceChildren(list, detail);
    renderRows();
    select(selected);
  };

  const renderRows = () => {
    tbody.replaceChildren(...visible.slice(0, 2000).map((p) => {
      const row = h('tr', { tabindex: '0', 'aria-selected': String(p === selected), onclick: () => select(p), onkeydown: (e) => {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          const i = visible.indexOf(p) + (e.key === 'ArrowDown' ? 1 : -1);
          if (visible[i]) {
            select(visible[i]);
            tbody.children[i]?.focus();
          }
        }
      } },
      [p.no, p.t.toFixed(6), p.src, p.dst, p.app ?? p.proto, p.len, p.info].map((v) => h('td', {}, String(v))));
      return row;
    }));
  };

  const select = (p) => {
    if (!p) {
      detail.replaceChildren(h('div', {}, 'No packet selected.'));
      return;
    }
    selected = p;
    [...tbody.children].forEach((row, i) => row.setAttribute('aria-selected', String(visible[i] === p)));
    const layers = [
      ['Frame', `${p.no}: ${p.len} bytes on wire, captured at ${p.t.toFixed(6)} seconds`],
      ['Internet Protocol', `Src: ${p.src}, Dst: ${p.dst}${p.ttl ? `, TTL: ${p.ttl}` : ''}`]
    ];
    if (p.proto === 'TCP') layers.push(['Transmission Control Protocol', `Src Port: ${p.sport}, Dst Port: ${p.dport}, Flags: [${p.flags ?? 'ACK'}]${p.seq !== undefined ? `, Seq: ${p.seq}` : ''}`]);
    if (p.proto === 'UDP') layers.push(['User Datagram Protocol', `Src Port: ${p.sport}, Dst Port: ${p.dport}`]);
    if (p.dns) layers.push(['Domain Name System', `${p.dns.response ? 'Response' : 'Query'} ${p.dns.id ?? ''}: ${p.dns.qtype ?? 'A'} ${p.dns.qname}${p.dns.answers?.length ? `\nAnswers: ${p.dns.answers.join(', ')}` : ''}`]);
    if (p.http) layers.push(['Hypertext Transfer Protocol', p.payload?.split('\r\n\r\n')[0] ?? '']);
    if (p.tls) layers.push(['Transport Layer Security', `${p.tls.type ?? 'Application Data'}${p.tls.sni ? `\nServer Name Indication: ${p.tls.sni}` : ''}${p.tls.version ? `\nVersion: ${p.tls.version}` : ''}`]);
    if (p.notes) layers.push(['Notes', p.notes]);
    detail.replaceChildren(
      h('div', {}, h('dl', {}, layers.map(([k, v]) => [h('dt', {}, k), h('dd', { style: 'white-space:pre-wrap' }, v)]))),
      h('div', {}, h('pre', {}, hexDump(latin1(p.payload ?? '')))));
    report({ type: 'select-packet', no: p.no });
  };

  const apply = () => {
    try {
      const test = compileFilter(filterInput.value);
      visible = packets.filter(test);
      filterInput.classList.remove('invalid');
      status.textContent = `Displayed: ${visible.length} of ${packets.length} packets`;
      report({ type: 'filter', filter: filterInput.value, count: visible.length });
      if (!visible.includes(selected)) selected = visible[0];
      showList();
    } catch (error) {
      if (!(error instanceof FilterError)) throw error;
      filterInput.classList.add('invalid');
      status.textContent = error.message;
    }
  };

  const follow = () => {
    if (!selected || !['TCP', 'UDP'].includes(selected.proto)) {
      status.textContent = 'Select a TCP or UDP packet first, then follow its stream.';
      return;
    }
    const key = streamKey(selected);
    const stream = packets.filter((p) => streamKey(p) === key && p.payload);
    // The client is whoever opened the connection. Without a SYN in the
    // capture, guess the side using the higher (ephemeral) port.
    const opener = packets.find((p) => streamKey(p) === key && p.flags === 'SYN');
    const client = opener ? opener.src : selected.sport > selected.dport ? selected.src : selected.dst;
    status.textContent = `Following ${selected.proto} stream ${selected.src}:${selected.sport} and ${selected.dst}:${selected.dport}. Red text was sent by the client, blue by the server.`;
    main.replaceChildren(h('div', { class: 'stream-view', role: 'document' }, stream.map((p) => h('span', { class: p.src === client ? 'c' : 's' }, p.payload + (p.payload.endsWith('\n') ? '' : '\n')))));
    report({ type: 'follow', key, packets: stream.map((p) => p.no) });
  };

  const conversations = () => {
    const groups = new Map();
    for (const p of visible) {
      const pair = [p.src, p.dst].sort().join(' and ');
      const g = groups.get(pair) ?? { pair, packets: 0, bytes: 0, first: p.t, last: p.t };
      g.packets++;
      g.bytes += p.len;
      g.last = p.t;
      groups.set(pair, g);
    }
    status.textContent = `${groups.size} conversations in the displayed packets.`;
    main.replaceChildren(h('div', { class: 'pcap-list', style: 'max-height:28rem' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Address A and B', 'Packets', 'Bytes', 'Duration (s)'].map((c) => h('th', {}, c)))),
      h('tbody', {}, [...groups.values()].sort((a, b) => b.bytes - a.bytes).map((g) => h('tr', {}, h('td', {}, g.pair), h('td', {}, String(g.packets)), h('td', {}, g.bytes.toLocaleString()), h('td', {}, (g.last - g.first).toFixed(2))))))));
    report({ type: 'conversations' });
  };

  filterForm.addEventListener('submit', (event) => {
    event.preventDefault();
    apply();
  });
  apply();
  return { apply: (f) => { filterInput.value = f; apply(); } };
}
