import { test, expect } from '@playwright/test';

test('should return oidc discovery configuration', async ({ request, baseURL }) => {
  const response = await request.get('/.well-known/openid-configuration');
  const oidcDiscovery = await response.json();

  expect(oidcDiscovery).toStrictEqual({
    issuer: baseURL,
    authorization_endpoint: `${baseURL}/api/oauth/authorize`,
    token_endpoint: `${baseURL}/api/oauth/token`,
    userinfo_endpoint: `${baseURL}/api/oauth/userinfo`,
    jwks_uri: `${baseURL}/oauth/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['plain', 'S256'],
  });
});
