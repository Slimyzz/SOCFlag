// Byte helpers shared by the shell, the tools page and the challenge content.
// Everything works on Uint8Array so binary data survives pipes and decoders.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

export function utf8(text) {
  return encoder.encode(String(text));
}

export function text(bytes) {
  return decoder.decode(bytes);
}

export function latin1(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

export function concat(...parts) {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function toHex(bytes, separator = '') {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(separator);
}

export function fromHex(hex) {
  const clean = String(hex).replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (clean.length % 2) throw new Error('Hex input has an odd number of digits.');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function toBase64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    out += B64[a >> 2];
    out += B64[((a & 3) << 4) | ((b ?? 0) >> 4)];
    out += b === undefined ? '=' : B64[((b & 15) << 2) | ((c ?? 0) >> 6)];
    out += c === undefined ? '=' : B64[c & 63];
  }
  return out;
}

export function fromBase64(input) {
  const clean = String(input).replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
  if (clean.length % 4 === 1) throw new Error('That is not valid Base64.');
  const out = [];
  let buffer = 0, bits = 0;
  for (const ch of clean) {
    buffer = (buffer << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function xor(data, key) {
  const out = new Uint8Array(data.length);
  if (!key.length) return out.set(data), out;
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
  return out;
}

export function rot(textValue, shift = 13) {
  return String(textValue).replace(/[a-z]/gi, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26 + 26) % 26 + base);
  });
}

export function isPrintable(byte) {
  return byte >= 0x20 && byte < 0x7f;
}

export function looksBinary(bytes) {
  const sample = bytes.subarray(0, 512);
  if (!sample.length) return false;
  let odd = 0;
  for (const b of sample) {
    if (b === 0) return true;
    if (!isPrintable(b) && b !== 9 && b !== 10 && b !== 13 && b < 0x80) odd++;
  }
  return odd / sample.length > 0.1;
}
