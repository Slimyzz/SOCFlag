// Analyst utilities: decoding, defanging, timestamps, hashing and pulling
// indicators out of text. The same small jobs a SOC analyst does all day.
import { h, copyText } from '../core/dom.js';
import { utf8, text, toHex, fromHex, toBase64, fromBase64, rot, isPrintable } from '../lib/bytes.js';
import { md5, sha1, sha256 } from '../lib/hash.js';

function readable(bytes) {
  // PowerShell's -EncodedCommand is Base64 of UTF-16LE text, so every second
  // byte is zero. Show it as text rather than a wall of hex.
  if (bytes.length >= 4 && bytes.length % 2 === 0 && bytes.every((b, i) => (i % 2 ? b === 0 : b !== 0))) {
    return `${String.fromCharCode(...bytes.filter((_, i) => i % 2 === 0))}\n\n(Decoded as UTF-16LE: every second byte was zero, which is how Windows stores text.)`;
  }
  const clean = bytes.every((b) => isPrintable(b) || b === 9 || b === 10 || b === 13 || b >= 0x80);
  return clean ? text(bytes) : `${text(bytes)}\n\n(Some bytes are not printable. As hex: ${toHex(bytes)})`;
}

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !(n >= 0 && n <= 255))) throw new Error(`${ip} is not a valid IPv4 address.`);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

// Punycode (RFC 3492) turns internationalised domain labels into ASCII that
// starts with xn--. Decoding shows which characters a lookalike really uses.
export function punycodeToUnicode(domain) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const adapt = (delta, points, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / points);
    let k = 0;
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (c) => (c >= 48 && c < 58 ? c - 22 : c >= 65 && c < 91 ? c - 65 : c >= 97 && c < 123 ? c - 97 : base);
  const decodeLabel = (label) => {
    if (!/^xn--/i.test(label)) return label;
    const input = label.slice(4);
    const split = input.lastIndexOf('-');
    const output = split > 0 ? [...input.slice(0, split)].map((c) => c.codePointAt(0)) : [];
    let n = 128, i = 0, bias = 72;
    for (let pos = split > 0 ? split + 1 : 0; pos < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        const d = digit(input.charCodeAt(pos++));
        if (d >= base || pos > input.length + 1) throw new Error(`${label} is not valid punycode.`);
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, output.length + 1, oldi === 0);
      n += Math.floor(i / (output.length + 1));
      i %= output.length + 1;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  };
  return domain.trim().toLowerCase().split('.').map(decodeLabel).join('.');
}

function describePunycode(input) {
  return input.trim().split(/\s+/).map((domain) => {
    const decoded = punycodeToUnicode(domain);
    const unusual = [...decoded].filter((ch) => ch.codePointAt(0) > 127).map((ch) => `${ch} is U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
    return `${domain}\n  displays as ${decoded}\n  ${unusual.length ? `non ASCII characters: ${unusual.join(', ')}` : 'plain ASCII'}`;
  }).join('\n\n');
}

export function extractIocs(input) {
  const unique = (list) => [...new Set(list)];
  const refanged = input.replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http').replace(/\[:\]/g, ':');
  const urls = unique(refanged.match(/https?:\/\/[^\s"'<>)\]]+/gi) ?? []);
  const emails = unique(refanged.match(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g) ?? []);
  const ips = unique((refanged.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []).filter((ip) => ip.split('.').every((n) => Number(n) <= 255)));
  const domains = unique((refanged.match(/\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|uk|ru|cn|info|biz|xyz|top|app|dev|online|site|live|me|us|de|example|test|internal|local)\b/gi) ?? []).map((d) => d.toLowerCase()))
    .filter((d) => !emails.some((e) => e.toLowerCase().endsWith('@' + d)) || urls.some((u) => u.toLowerCase().includes(d)));
  const hashes = unique(refanged.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) ?? []);
  const sections = [['URLs', urls], ['Domains', domains], ['IP addresses', ips], ['Email addresses', emails], ['Hashes', hashes.map((x) => `${x} (${{ 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' }[x.length]})`)]];
  return sections.map(([name, items]) => `${name} (${items.length})\n${items.map((i) => `  ${i}`).join('\n') || '  none'}`).join('\n\n');
}

const OPS = [
  { id: 'b64d', label: 'Base64 decode', run: (s) => readable(fromBase64(s.trim())) },
  { id: 'b64e', label: 'Base64 encode', run: (s) => toBase64(utf8(s)) },
  { id: 'hexd', label: 'Hex decode', run: (s) => readable(fromHex(s)) },
  { id: 'hexe', label: 'Hex encode', run: (s) => toHex(utf8(s)) },
  { id: 'urld', label: 'URL decode', run: (s) => decodeURIComponent(s.replace(/\+/g, ' ')) },
  { id: 'urle', label: 'URL encode', run: (s) => encodeURIComponent(s) },
  { id: 'rot13', label: 'ROT13', run: (s) => rot(s, 13) },
  { id: 'rev', label: 'Reverse', run: (s) => [...s].reverse().join('') },
  { id: 'defang', label: 'Defang', run: (s) => s.replace(/https?/gi, (m) => m.replace(/tt/i, 'xx')).replace(/\./g, '[.]').replace(/:\/\//g, '[:]//') },
  { id: 'refang', label: 'Refang', run: (s) => s.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':').replace(/hxxp/gi, 'http') },
  { id: 'iocs', label: 'Extract indicators', run: extractIocs },
  { id: 'puny', label: 'Punycode decode', hint: 'One domain per line, like xn--bcher-kva.example.', run: describePunycode },
  { id: 'epoch', label: 'Unix time to date', run: (s) => s.trim().split(/\s+/).map((n) => {
    const v = Number(n);
    if (!Number.isFinite(v)) return `${n}: not a number`;
    const ms = v > 1e12 ? v : v * 1000;
    return `${n}  ${new Date(ms).toISOString()}`;
  }).join('\n') },
  { id: 'todate', label: 'Date to Unix time', run: (s) => {
    const ms = Date.parse(s.trim());
    if (Number.isNaN(ms)) throw new Error('Could not read that date. Try a format like 2026-03-13T06:41:08Z.');
    return `${Math.floor(ms / 1000)} seconds\n${ms} milliseconds`;
  } },
  { id: 'hash', label: 'Hash (MD5, SHA-1, SHA-256)', run: (s) => `MD5      ${md5(s)}\nSHA-1    ${sha1(s)}\nSHA-256  ${sha256(s)}` },
  { id: 'cidr', label: 'Is IP in range?', hint: 'One range on the first line (like 10.0.0.0/8), then one IP per line.', run: (s) => {
    const [range, ...ips] = s.trim().split(/\s+/);
    const [base, bits] = range.split('/');
    const size = Number(bits);
    if (!(size >= 0 && size <= 32)) throw new Error('Put a range like 192.168.0.0/16 on the first line.');
    const mask = size === 0 ? 0 : (0xffffffff << (32 - size)) >>> 0;
    const net = ipToInt(base) & mask;
    const first = net, last = (net | (~mask >>> 0)) >>> 0;
    const fmt = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    return `${range}: ${fmt(first)} to ${fmt(last)} (${(last - first + 1).toLocaleString()} addresses)\n\n` + ips.map((ip) => `${ip.padEnd(16)} ${(ipToInt(ip) & mask) === net ? 'inside' : 'outside'}`).join('\n');
  } },
  { id: 'jwt', label: 'Read a JWT', run: (s) => {
    const parts = s.trim().split('.');
    if (parts.length < 2) throw new Error('A JWT has three parts separated by dots.');
    const decode = (p) => JSON.stringify(JSON.parse(text(fromBase64(p))), null, 2);
    return `Header\n${decode(parts[0])}\n\nPayload\n${decode(parts[1])}\n\nThe signature is not checked here. Reading a token is not the same as trusting it.`;
  } }
];

export function mountTools(host, spec = {}, report = () => {}) {
  let op = OPS.find((o) => o.id === spec.op) ?? OPS[0];
  const input = h('textarea', { class: 'field', rows: 6, spellcheck: 'false', 'aria-label': 'Input' });
  const output = h('pre', { class: 'bench-out', 'aria-live': 'polite' });
  const hint = h('p', { class: 'muted small' });
  const buttons = OPS.map((o) => h('button', { type: 'button', 'aria-pressed': String(o === op), onclick: () => { op = o; buttons.forEach((b, i) => b.setAttribute('aria-pressed', String(OPS[i] === op))); run(); } }, o.label));

  function run() {
    hint.textContent = op.hint ?? '';
    if (!input.value) {
      output.className = 'bench-out';
      output.textContent = 'Output appears here.';
      return;
    }
    try {
      output.className = 'bench-out';
      output.textContent = op.run(input.value);
      report({ type: 'tool', op: op.id });
    } catch (error) {
      output.className = 'bench-out err';
      output.textContent = error.message?.includes('URI') ? 'That is not valid URL encoding.' : error.message;
    }
  }
  input.addEventListener('input', run);

  const artifacts = (spec.artifacts ?? []).map((a) => h('div', { class: 'artifact' },
    h('div', { class: 'artifact-head' }, h('span', {}, a.name), h('span', { class: 'row' },
      h('button', { class: 'btn small', type: 'button', onclick: () => { input.value = a.content; run(); } }, 'Use as input'),
      h('button', { class: 'btn small', type: 'button', onclick: () => copyText(a.content) }, 'Copy'))),
    a.note ? h('p', { class: 'muted small', style: 'margin:.3rem 0 0' }, a.note) : null,
    h('pre', {}, a.content)));

  host.replaceChildren(...artifacts, h('div', { class: 'bench' },
    h('div', { class: 'bench-ops', role: 'group', 'aria-label': 'Operation' }, buttons),
    h('div', {}, h('div', { class: 'bench-head' }, h('label', {}, 'Input'), h('span', { class: 'row' },
      h('button', { class: 'btn small', type: 'button', onclick: () => { input.value = output.textContent; run(); } }, 'Output to input'),
      h('button', { class: 'btn small', type: 'button', onclick: () => copyText(output.textContent) }, 'Copy output'))), input),
    hint,
    h('div', {}, h('div', { class: 'bench-head' }, h('label', {}, 'Output')), output)));
  run();
  return { input, run };
}
