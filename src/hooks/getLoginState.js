import { Debug } from '../debug.js';

const debug = Debug('getLoginState');

/**
 * Default login state, carries the URL to return to after login
 * @param {import('express').Request} req
 * @param {any} options
 * @returns {Record<string, any>}
 */
export function defaultState(req, options) {
  const state = { returnTo: options.returnTo || req.originalUrl };
  debug('adding default state %O', state);
  return state;
}

/**
 * Encode login state as the authorization request `state` parameter
 * @param {any} stateObject
 */
export function encodeState(stateObject = {}) {
  const { nonce, code_verifier, max_age, ...filteredState } = stateObject;
  return Buffer.from(JSON.stringify(filteredState)).toString('base64url');
}

/**
 * Decode the `state` parameter back into login state
 * @param {string} stateValue
 */
export function decodeState(stateValue) {
  try {
    // @ts-ignore
    return JSON.parse(Buffer.from(stateValue, 'base64'));
  } catch {
    return false;
  }
}
