const ALGORITHMS = new Map([
  ['sha256', 32],
  ['sha384', 48],
  ['sha512', 64],
]);

/**
 * Parses an SRI integrity attribute value into a list of metadata objects.
 *
 * The SRI spec (Subresource Integrity, W3C) defines an integrity metadata
 * value as a space-separated list of "algorithm-hash" pairs. Each pair is
 * either "<alg>-<base64>" or "<alg>-<base64>?<options>". The options are
 * only useful for future extensibility; we ignore them.
 *
 * We validate that the decoded hash length matches the digest size of the
 * declared algorithm. This catches the common copy-paste error of using a
 * SHA-512 hash with a sha256 label.
 *
 * @param {string} value - The raw integrity attribute value.
 * @returns {Array<{algorithm: string, hash: string, options: string[]}>}
 * @throws {TypeError} If value is not a string.
 * @throws {Error} If any token is malformed or has an invalid hash length.
 */
export function parseIntegrity(value) {
  if (typeof value !== 'string') {
    throw new TypeError('integrity value must be a string');
  }

  const tokens = value.trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    throw new Error('integrity value is empty');
  }

  const result = [];
  for (const token of tokens) {
    const parsed = parseToken(token);
    result.push(parsed);
  }
  return result;
}

/**
 * Parses a single integrity metadata token.
 *
 * The token format is:
 *   algorithm '-' base64-hash [ '?' options ]
 * where algorithm is one of sha256, sha384, sha512 (case-insensitive).
 *
 * We split on the first '-' rather than using a regex because the hash part
 * can contain '-' in its base64 alphabet? Actually base64 standard alphabet
 * does not contain '-' (it uses '+' and '/'), but base64url does. SRI uses
 * standard base64 with padding, so '-' is not part of the hash. Splitting on
 * the first '-' is safe and avoids a complex regex.
 *
 * @param {string} token
 * @returns {{algorithm: string, hash: string, options: string[]}}
 */
function parseToken(token) {
  const dashIndex = token.indexOf('-');
  if (dashIndex === -1) {
    throw new Error(`invalid integrity token (missing '-'): ${token}`);
  }

  const algorithm = token.slice(0, dashIndex).toLowerCase();
  const rest = token.slice(dashIndex + 1);

  if (!ALGORITHMS.has(algorithm)) {
    throw new Error(`unsupported algorithm: ${algorithm}`);
  }

  let hash = rest;
  let options = [];
  const questionIndex = rest.indexOf('?');
  if (questionIndex !== -1) {
    hash = rest.slice(0, questionIndex);
    const optionsPart = rest.slice(questionIndex + 1);
    options = optionsPart.split('?').filter(Boolean);
  }

  if (hash.length === 0) {
    throw new Error(`empty hash for algorithm ${algorithm}`);
  }

  const decoded = decodeBase64(hash);
  const expectedLength = ALGORITHMS.get(algorithm);
  if (decoded.length !== expectedLength) {
    throw new Error(
      `hash length mismatch for ${algorithm}: expected ${expectedLength} bytes, got ${decoded.length}`
    );
  }

  return { algorithm, hash, options };
}

/**
 * Decodes a base64 string to a Uint8Array.
 *
 * We use Buffer when available (Node.js) for speed and correctness, but fall
 * back to a pure JS implementation for environments without Buffer (e.g.
 * browsers or other runtimes). The fallback is intentionally simple and only
 * handles the standard base64 alphabet with optional padding.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
function decodeBase64(str) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(str, 'base64'));
  }

  // Fallback: atob is available in browsers and web workers.
  if (typeof atob === 'function') {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  throw new Error('no base64 decoder available');
}
