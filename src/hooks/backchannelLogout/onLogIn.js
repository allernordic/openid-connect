import { getClient } from '../../client.js';

/**
 * Default hook that clears earlier Back-Channel Logouts for the user logging in
 * @param {import('express').Request} req
 * @param {import('types').ConfigParams} config
 */
export async function onLogIn(req, config) {
  const {
    issuer: { issuer },
  } = await getClient(config);
  const { session, backchannelLogout } = config;
  // @ts-ignore
  const store = backchannelLogout?.store || session.store;

  const { sub, sid } = req.oidc.idTokenClaims;

  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;

  // entries may be keyed by the issuer with or without a trailing slash
  const keys = [
    `${normalizedIssuer}|${sub}`,
    `${normalizedIssuer}/|${sub}`,
    sid && `${normalizedIssuer}|${sid}`,
    sid && `${normalizedIssuer}/|${sid}`,
  ].filter(Boolean);

  await Promise.all(keys.map((key) => store.destroy(key)));
}
