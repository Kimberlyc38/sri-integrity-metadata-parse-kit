import test from 'node:test';
import assert from 'node:assert/strict';
import { parseIntegrity } from '../src/index.js';

// Helper to create a valid base64 hash of a given length.
function makeHash(byteLength) {
  const bytes = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    bytes[i] = i;
  }
  return Buffer.from(bytes).toString('base64');
}

test('parses a single sha256 hash', () => {
  const hash = makeHash(32);
  const result = parseIntegrity(`sha256-${hash}`);
  assert.deepEqual(result, [{ algorithm: 'sha256', hash, options: [] }]);
});

test('parses multiple hashes separated by whitespace', () => {
  const h256 = makeHash(32);
  const h384 = makeHash(48);
  const result = parseIntegrity(`  sha256-${h256}\t sha384-${h384}  `);
  assert.deepEqual(result, [
    { algorithm: 'sha256', hash: h256, options: [] },
    { algorithm: 'sha384', hash: h384, options: [] },
  ]);
});

test('algorithm is case-insensitive', () => {
  const hash = makeHash(32);
  const result = parseIntegrity(`SHA256-${hash}`);
  assert.deepEqual(result, [{ algorithm: 'sha256', hash, options: [] }]);
});

test('parses options after a question mark', () => {
  const hash = makeHash(32);
  const result = parseIntegrity(`sha256-${hash}?foo?bar`);
  assert.deepEqual(result, [{ algorithm: 'sha256', hash, options: ['foo', 'bar'] }]);
});

test('rejects an empty string', () => {
  assert.throws(() => parseIntegrity(''), /empty/);
});

test('rejects a string with only whitespace', () => {
  assert.throws(() => parseIntegrity('   '), /empty/);
});

test('rejects a token without a dash', () => {
  assert.throws(() => parseIntegrity('sha256'), /missing/);
});

test('rejects an unsupported algorithm', () => {
  assert.throws(() => parseIntegrity('md5-abc'), /unsupported algorithm/);
});

test('rejects an empty hash', () => {
  assert.throws(() => parseIntegrity('sha256-'), /empty hash/);
});

test('rejects a hash with the wrong length', () => {
  const shortHash = makeHash(16);
  assert.throws(() => parseIntegrity(`sha256-${shortHash}`), /hash length mismatch/);
});

test('rejects a non-string input', () => {
  assert.throws(() => parseIntegrity(42), TypeError);
});

test('accepts a hash with padding and options', () => {
  const hash = makeHash(64);
  const result = parseIntegrity(`sha512-${hash}?`);
  assert.deepEqual(result, [{ algorithm: 'sha512', hash, options: [] }]);
});
