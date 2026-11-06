module.exports = {
  defaultRedirectUrl: 'http://localhost:3366/sso/oauth/oidc',
  redirectUrl: '["http://localhost:3366"]',
  tenant: 'oidc.example.com',
  product: 'crm',
  name: 'OIDC Metadata for oidc.example.com',
  description: 'OIDC Metadata for oidc.example.com',
  oidcDiscoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
  oidcClientId: 'dummyClientId',
  oidcClientSecret: 'dummyClientSecret',
};
