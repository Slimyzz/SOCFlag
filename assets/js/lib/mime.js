// Parses raw email source the way a mail client or an analyst's tool would:
// unfolds headers, splits multipart bodies, and decodes Base64 and
// quoted-printable parts. Enough for phishing analysis labs.
import { latin1, fromBase64, text } from './bytes.js';

export function parseHeaders(block) {
  const unfolded = block.replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ');
  return unfolded.split('\n').filter(Boolean).map((line) => {
    const index = line.indexOf(':');
    return index < 0 ? { name: '', value: line } : { name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() };
  });
}

export function header(headers, name) {
  return headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? '';
}

function params(value) {
  const out = {};
  for (const m of value.matchAll(/;\s*([\w-]+)=("([^"]*)"|[^;\s]+)/g)) out[m[1].toLowerCase()] = m[3] ?? m[2];
  return out;
}

function decodeQuotedPrintable(body) {
  return latin1(body.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))));
}

// Decodes =?utf-8?B?...?= style encoded words used in subjects and names.
export function decodeWords(value) {
  return value.replace(/=\?([\w-]+)\?([BQ])\?([^?]*)\?=/gi, (_, charset, kind, data) => {
    try {
      const bytes = kind.toUpperCase() === 'B' ? fromBase64(data) : decodeQuotedPrintable(data.replace(/_/g, ' '));
      return text(bytes);
    } catch {
      return data;
    }
  });
}

function splitMessage(raw) {
  const normalised = raw.replace(/\r\n/g, '\n');
  const index = normalised.indexOf('\n\n');
  return index < 0 ? [normalised, ''] : [normalised.slice(0, index), normalised.slice(index + 2)];
}

export function parsePart(raw) {
  const [head, body] = splitMessage(raw);
  const headers = parseHeaders(head);
  const contentType = header(headers, 'Content-Type') || 'text/plain';
  const type = contentType.split(';')[0].trim().toLowerCase();
  const p = params(contentType);
  const disposition = header(headers, 'Content-Disposition');
  const filename = params(disposition).filename ?? p.name ?? null;
  if (type.startsWith('multipart/') && p.boundary) {
    const pieces = body.split(`--${p.boundary}`).slice(1);
    const parts = [];
    for (const piece of pieces) {
      if (piece.startsWith('--')) break;
      parts.push(parsePart(piece.replace(/^\n/, '')));
    }
    return { headers, type, parts, filename };
  }
  const encoding = header(headers, 'Content-Transfer-Encoding').toLowerCase();
  let bytes;
  if (encoding === 'base64') bytes = fromBase64(body);
  else if (encoding === 'quoted-printable') bytes = decodeQuotedPrintable(body);
  else bytes = latin1(body);
  return { headers, type, bytes, filename: filename ? decodeWords(filename) : null, encoding };
}

export function flatten(part, out = []) {
  if (part.parts) part.parts.forEach((p) => flatten(p, out));
  else out.push(part);
  return out;
}

// Turns HTML into plain text an analyst can read safely, showing where each
// link really points next to the text it displays.
export function htmlToSafeText(html) {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, '')
    .replace(/<a\b[^>]*href\s*=\s*["']?([^"' >]+)["']?[^>]*>([\s\S]*?)<\/a>/gi, (_, href, label) => `${label.replace(/<[^>]+>/g, '').trim()} [link: ${href}]`)
    .replace(/<img\b[^>]*src\s*=\s*["']?([^"' >]+)["']?[^>]*>/gi, '[image: $1]')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|h\d|li)>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function parseMessage(raw) {
  const root = parsePart(raw);
  const leaves = flatten(root);
  const textPart = leaves.find((p) => p.type === 'text/plain' && !p.filename);
  const htmlPart = leaves.find((p) => p.type === 'text/html' && !p.filename);
  const attachments = leaves.filter((p) => p.filename);
  return {
    headers: root.headers,
    from: decodeWords(header(root.headers, 'From')),
    to: decodeWords(header(root.headers, 'To')),
    subject: decodeWords(header(root.headers, 'Subject')),
    date: header(root.headers, 'Date'),
    text: textPart ? text(textPart.bytes) : null,
    html: htmlPart ? text(htmlPart.bytes) : null,
    attachments
  };
}
