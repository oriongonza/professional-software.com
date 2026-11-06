// Versioned encrypted package; no password or report data is stored in this module.
const MAGIC = new TextEncoder().encode('PSREP001');
const ITERATIONS = 600_000;
const HEADER_SIZE = 8 + 16 + 12;
const MAX_BYTES = 20 * 1024 * 1024;

async function keyFromPassword(password, salt, usage) {
  if (typeof password !== 'string' || !password || password.length > 256) {
    throw new Error('Invalid password length');
  }
  const bytes = new TextEncoder().encode(password);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      {name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS},
      material, {name: 'AES-GCM', length: 256}, false, [usage],
    );
  } finally {
    bytes.fill(0);
  }
}

export async function encryptPackage(plaintext, password) {
  if (!(plaintext instanceof Uint8Array) || plaintext.length > MAX_BYTES) throw new Error('Invalid package size');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC); header.set(salt, 8); header.set(iv, 24);
  const key = await keyFromPassword(password, salt, 'encrypt');
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {name: 'AES-GCM', iv, additionalData: header, tagLength: 128}, key, plaintext,
  ));
  const result = new Uint8Array(HEADER_SIZE + ciphertext.length);
  result.set(header); result.set(ciphertext, HEADER_SIZE);
  return result;
}

export async function decryptPackage(envelope, password) {
  const bytes = envelope instanceof Uint8Array ? envelope : new Uint8Array(envelope);
  if (bytes.length < HEADER_SIZE + 16 || bytes.length > MAX_BYTES + HEADER_SIZE + 16 ||
      !MAGIC.every((byte, i) => bytes[i] === byte)) throw new Error('Invalid package');
  const header = bytes.slice(0, HEADER_SIZE), salt = bytes.slice(8, 24), iv = bytes.slice(24, HEADER_SIZE);
  const key = await keyFromPassword(password, salt, 'decrypt');
  return new Uint8Array(await crypto.subtle.decrypt(
    {name: 'AES-GCM', iv, additionalData: header, tagLength: 128}, key, bytes.slice(HEADER_SIZE),
  ));
}
