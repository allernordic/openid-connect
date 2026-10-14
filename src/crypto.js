import { hkdfSync, timingSafeEqual } from 'node:crypto';

import { FlattenedSign, CompactEncrypt, compactDecrypt } from 'jose';

const BYTE_LENGTH = 32;
const ENCRYPTION_INFO = 'JWE CEK';
const SIGNING_INFO = 'JWS Cookie Signing';
const DIGEST = 'sha256';
const ALG = 'HS256';
const CRITICAL_HEADER_PARAMS = ['b64'];

const header = { alg: ALG, b64: false, crit: CRITICAL_HEADER_PARAMS };

/**
 * Get cookie encryption keys
 * @param {string|Buffer|Array<string|Buffer>} secret secret or secrets
 * @returns {[Buffer, Buffer[]]} tuple with secrets [current, [current, ...]]
 */
export function getEncryptionKeyStore(secret) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = secrets.map((s) => encryption(s));
  return [keystore[0], keystore];
}

/**
 * Get cookie signing keys
 * @param {string|Buffer|Array<string|Buffer>} secret secret or secrets
 * @returns {[Buffer, Buffer[]]} tuple with secrets [current, [current, ...]]
 */
export function getSigningKeyStore(secret) {
  const secrets = Array.isArray(secret) ? secret : [secret];
  const keystore = secrets.map((s) => signing(s));
  return [keystore[0], keystore];
}

/**
 * Verify cookie signature
 * @param {string} cookie
 * @param {string} value
 * @param {Buffer[]} keystore
 */
export async function verifyCookie(cookie, value, keystore) {
  if (!value) return;

  const [part, signature] = value.split('.');
  if (await verifySignature(cookie, part, signature, keystore)) {
    return part;
  }
}

/**
 * Sign cookie
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {Buffer} key signing key
 */
export async function signCookie(cookie, value, key) {
  const signature = await generateSignature(cookie, value, key);
  return `${value}.${signature}`;
}

/**
 * Encrypt cookie
 * @param {Buffer} key encryption key
 * @param {string} payload encrypt payload
 * @param {Record<string, any>} [headers] extra headers
 */
export async function encrypt(key, payload, headers) {
  const encrypted = await new CompactEncrypt(Buffer.from(payload))
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', ...headers })
    .encrypt(key);

  return encrypted;
}

/**
 * Decrypt cookie
 * @param {Buffer|Buffer[]} keystore
 * @param {string} jweCompact
 */
export async function decrypt(keystore, jweCompact) {
  const keysToTry = Array.isArray(keystore) ? keystore : [keystore];

  for (const key of keysToTry) {
    try {
      const { protectedHeader, plaintext } = await compactDecrypt(jweCompact, key);

      return { header: protectedHeader, payload: new TextDecoder().decode(plaintext) };
    } catch (error) {
      // eslint-disable-next-line no-var
      var lastError = error;
    }
  }

  throw lastError;
}

/**
 * Generate cookie signature
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {Buffer} key signature key
 */
async function generateSignature(cookie, value, key) {
  return (await new FlattenedSign(Buffer.from(`${cookie}=${value}`)).setProtectedHeader(header).sign(key)).signature;
}

/**
 * Verify cookie signature
 * @param {string} cookie cookie name
 * @param {string} value cookie value
 * @param {string} signature cookie signature
 * @param {Buffer[]} keystore signature secrets key store
 */
async function verifySignature(cookie, value, signature, keystore) {
  try {
    for (const key of keystore) {
      const expectedSignature = await generateSignature(cookie, value, key);
      if (timingSafeEqual(Buffer.from(signature, 'base64url'), Buffer.from(expectedSignature, 'base64url'))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Derive the cookie encryption key from a secret
 * @param {string|Buffer} secret
 */
function encryption(secret) {
  return Buffer.from(hkdfSync(DIGEST, secret, Buffer.alloc(0), ENCRYPTION_INFO, BYTE_LENGTH));
}

/**
 * Derive the cookie signing key from a secret
 * @param {string|Buffer} secret
 */
function signing(secret) {
  return Buffer.from(hkdfSync(DIGEST, secret, Buffer.alloc(0), SIGNING_INFO, BYTE_LENGTH));
}
