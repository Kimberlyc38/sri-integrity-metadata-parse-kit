# sri-integrity-metadata-parse-kit

Parses Subresource Integrity (SRI) attribute values, splitting them into algorithm-hash pairs and validating that each hash has the correct length for its declared algorithm.

## Usage

```js
import { parseIntegrity } from 'sri-integrity-metadata-parse-kit';

const metadata = parseIntegrity('sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
console.log(metadata);
// [
//   { algorithm: 'sha256', hash: '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=', options: [] },
// ]
```

The function throws an `Error` if the input is malformed, uses an unsupported algorithm, or has a hash whose decoded length does not match the algorithm's digest size. It throws a `TypeError` if the input is not a string.

## Why this exists

SRI is a security feature that lets you pin the exact hash of a script or stylesheet. Browsers ignore invalid integrity metadata, but server-side tooling often needs to parse and validate it. The common mistake is to trust the algorithm label without checking the hash length: a SHA-512 hash mislabeled as `sha256` will be silently accepted by a naive parser. This library rejects that, so you catch misconfigurations early.

The trade-off is strictness: we only support the three algorithms defined in the SRI spec (`sha256`, `sha384`, `sha512`). If you need to parse experimental algorithms, this library will reject them. We also ignore the optional `?` options entirely, since the spec does not define any semantics for them yet; they are returned as an array of strings for future use.

## Edge cases

- Whitespace around and between tokens is trimmed and collapsed.
- Algorithm names are case-insensitive.
- A trailing `?` with no options yields an empty options array.
- A hash that is valid base64 but decodes to the wrong number of bytes is rejected.
- The parser does not verify that the hash is cryptographically correct; it only checks length.

## API

### `parseIntegrity(value: string): Array<{ algorithm: string, hash: string, options: string[] }>`

Parses an integrity attribute value. Throws on invalid input.
