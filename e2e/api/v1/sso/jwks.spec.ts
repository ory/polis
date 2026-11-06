import { test, expect } from '@playwright/test';

test('should return public key in jwk format', async ({ request }) => {
  const response = await request.get('/oauth/jwks');
  const jwks = await response.json();
  const jose = await import('jose');

  const spki = Buffer.from(process.env.OPENID_RSA_PUBLIC_KEY || '', 'base64').toString('ascii');
  const importedPublicKey = await jose.importSPKI(spki, process.env.OPENID_JWS_ALG || '');

  const publicKeyJWK = await jose.exportJWK(importedPublicKey);
  const jwkThumbprint = await jose.calculateJwkThumbprint(publicKeyJWK);

  expect(jwks).toStrictEqual({
    keys: [
      {
        ...publicKeyJWK,
        kid: jwkThumbprint,
        alg: process.env.OPENID_JWS_ALG,
        use: 'sig',
      },
    ],
  });
});
