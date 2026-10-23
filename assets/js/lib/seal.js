// Flags are never stored as plain text. Each one is XORed with a keystream
// derived from its challenge id and stored as Base64, so searching the source
// for "HW{" finds nothing. This keeps answers out of sight; it is not real
// secrecy, because the page has to be able to check your answer. See
// docs/security-model.md.
import { utf8, text, concat, xor, toBase64, fromBase64 } from './bytes.js';
import { sha256Bytes } from './hash.js';

function keystream(id, length) {
  const key = sha256Bytes(`hiddenwell/v3/${id}`);
  const blocks = [];
  for (let i = 0; blocks.length * 32 < length; i++) {
    blocks.push(sha256Bytes(concat(key, Uint8Array.of(i >>> 24, i >>> 16 & 255, i >>> 8 & 255, i & 255))));
  }
  return concat(...blocks).subarray(0, length);
}

export function seal(id, flag) {
  const plain = utf8(flag);
  return toBase64(xor(plain, keystream(id, plain.length)));
}

export function unseal(id, sealed) {
  const data = fromBase64(sealed);
  return text(xor(data, keystream(id, data.length)));
}

export function normaliseFlag(value) {
  return String(value ?? '').trim().toLowerCase();
}
