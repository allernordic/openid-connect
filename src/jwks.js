import { createRemoteJWKSet } from 'jose';

const cache = new Map();

/**
 * Get a remote JWKS resolver for a JWKS URI, shared across callers so keys are not refetched on every verification
 * @param {string | URL} jwksUri
 * @returns {ReturnType<typeof createRemoteJWKSet>}
 */
export function getRemoteJWKSet(jwksUri) {
  const key = jwksUri.toString();
  let jwks = cache.get(key);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(jwksUri));
    cache.set(key, jwks);
  }
  return jwks;
}
