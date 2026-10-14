import { jwtVerify } from 'jose';

import { Debug } from '../debug.js';
import { UnauthorizedError } from '../errors.js';
import { getRemoteJWKSet } from '../jwks.js';

const debug = Debug('requiresBearerAuth');

/**
 * Protect JSON API routes with an OAuth2 bearer access token (JWT) issued by the issuer for `audience`,
 * e.g. for cross-origin AJAX callers or other services.
 *
 * The verified token is exposed as `req.bearerAuth = { payload, protectedHeader, token }`, and the
 * `requiresAuth` family can be chained after this middleware to authorize on its claims. A missing or
 * invalid token is rejected with an `UnauthorizedError` (401) whose `headers` carry the `WWW-Authenticate`
 * challenge to apply to the response. With `fallthrough: true` a request without a token continues unauthenticated.
 *
 * @param {import('types').BearerAuthParams} params
 * @returns {import('express').RequestHandler}
 */
export function requiresBearerAuth(params) {
  const { issuerBaseURL, audience, clockTolerance = 60, fallthrough = false } = params || {};
  if (!issuerBaseURL) throw new TypeError('"issuerBaseURL" is required');
  if (!audience) throw new TypeError('"audience" is required');

  // the base must end with a slash, or relative resolution drops its last path segment
  const discoveryUrl = new URL('.well-known/openid-configuration', issuerBaseURL.endsWith('/') ? issuerBaseURL : `${issuerBaseURL}/`);

  /** @type {ReturnType<typeof discoverIssuer> | undefined} */
  let verifier;

  return async function bearerAuthMiddleware(req, _res, next) {
    const match = /^Bearer +(\S+)$/i.exec(req.get('authorization') || '');
    if (!match) {
      if (fallthrough) {
        debug('no bearer token presented, falling through to the next handler');
        return next();
      }
      debug('no bearer token presented');
      return next(new UnauthorizedError('A bearer token is required for this route.', { 'WWW-Authenticate': 'Bearer' }));
    }
    const token = match[1];

    try {
      verifier = verifier || discoverIssuer(discoveryUrl);
      const { issuer, jwks } = await verifier.catch((err) => {
        verifier = undefined;
        throw err;
      });
      const { payload, protectedHeader } = await jwtVerify(token, jwks, { issuer, audience, clockTolerance });
      req.bearerAuth = { payload, protectedHeader, token };
    } catch (/** @type {any} */ err) {
      debug('bearer token rejected: %s', err.message);
      return next(new UnauthorizedError('Invalid bearer token.', { 'WWW-Authenticate': 'Bearer error="invalid_token"' }));
    }
    next();
  };
}

/**
 * Resolve the issuer identifier and JWKS from the OIDC discovery document
 * @param {URL} discoveryUrl
 */
async function discoverIssuer(discoveryUrl) {
  const response = await fetch(discoveryUrl);
  if (!response.ok) {
    throw new Error(`Discovery request to ${discoveryUrl} failed with status ${response.status}`);
  }
  const metadata = /** @type {{issuer?: string, jwks_uri?: string}} */ (await response.json());
  if (!metadata.issuer || !metadata.jwks_uri) {
    throw new Error('No issuer or JWKS URI found in issuer metadata');
  }
  return { issuer: metadata.issuer, jwks: getRemoteJWKSet(metadata.jwks_uri) };
}
