import { promisify } from 'node:util';

/**
 * Express-session compatible session store base class, for callback based session stores.
 *
 * Session store factories that expect the express-session module can be instantiated
 * with `auth`, which exposes this class as `auth.Store`.
 * @constructor
 */
export function Store() {}

/**
 * Get a promise based interface to a session store
 * @param {any} store
 * @returns {any} promise based session store
 */
export function promisifyStore(store) {
  if (!(store instanceof Store)) return store;
  const callbackStore = /** @type {any} */ (store);
  return {
    get: promisify(callbackStore.get.bind(callbackStore)),
    set: promisify(callbackStore.set.bind(callbackStore)),
    destroy: promisify(callbackStore.destroy.bind(callbackStore)),
  };
}
