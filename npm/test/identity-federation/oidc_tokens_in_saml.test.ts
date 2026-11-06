import tap from 'tap';
import { promisify } from 'util';
import { deflateRaw } from 'zlib';
import * as utils from '../../src/controller/utils';
import type { Configuration } from 'openid-client';

const deflateRawAsync = promisify(deflateRaw);

import type {
  IIdentityFederationController,
  IConnectionAPIController,
  IOAuthController,
  IdentityFederationApp,
  OIDCSSORecord,
  JacksonOption,
  Profile,
} from '../../src';

// Independent test configuration
const testConfig = {
  tenant: 'oidc-tokens-test-tenant',
  product: 'oidc-tokens-test-product',
  serviceProvider: {
    entityId: 'https://sp.oidc-tokens-test.example.com/saml/entityId',
    acsUrl: 'https://sp.oidc-tokens-test.example.com/saml/acs',
  },
};

// Independent Jackson options for this test
const jacksonOptions: JacksonOption = {
  externalUrl: 'https://my-cool-app.com',
  samlAudience: 'https://saml.boxyhq.com',
  samlPath: '/sso/oauth/saml',
  oidcPath: '/sso/oauth/oidc',
  db: {
    engine: 'mem',
  },
  clientSecretVerifier: 'TOP-SECRET',
  openid: {
    jwtSigningKeys: { private: 'PRIVATE_KEY', public: 'PUBLIC_KEY' },
    jwsAlg: 'RS256',
  },
  boxyhqLicenseKey: 'dummy-license',
  noAnalytics: true,
};

// OIDC connection configuration
const oidcConnectionConfig = {
  tenant: testConfig.tenant,
  product: testConfig.product,
  defaultRedirectUrl: 'http://localhost:3366/sso/oauth/oidc',
  redirectUrl: '["http://localhost:3366"]',
  oidcDiscoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
  oidcClientId: 'test-client-id',
  oidcClientSecret: 'test-client-secret',
};

// Mock user data from OIDC provider
const mockUserData = {
  sub: 'user-123',
  email: 'testuser@example.com',
  given_name: 'Test',
  family_name: 'User',
};

// Mock OIDC tokens
const mockOidcTokens = {
  id_token: 'mock-id-token-jwt',
  access_token: 'mock-access-token',
  refresh_token: 'mock-refresh-token',
  token_type: 'Bearer',
  expires_at: Math.floor(Date.now() / 1000) + 3600,
  scope: 'openid profile email',
};

let oauthController: IOAuthController;
let identityFederationController: IIdentityFederationController;
let connectionAPIController: IConnectionAPIController;

let code_verifier: string;
let code_challenge: string;
let openIdClientMock: typeof import('openid-client');
let utilsMock: any;

tap.before(async () => {
  const client = await import('openid-client');
  code_verifier = client.randomPKCECodeVerifier();
  code_challenge = await client.calculatePKCECodeChallenge(code_verifier);

  openIdClientMock = {
    ...client,
    randomPKCECodeVerifier: () => code_verifier,
    calculatePKCECodeChallenge: async () => code_challenge,
  };

  // Create mock for utils module with support for includeOidcTokensInAssertion
  utilsMock = tap.createMock(utils, {
    ...utils,
    dynamicImport: async (packageName) => {
      if (packageName === 'openid-client') {
        return openIdClientMock;
      }
      return utils.dynamicImport(packageName);
    },
    extractOIDCUserProfile: async (
      tokens: utils.AuthorizationCodeGrantResult,
      oidcConfig: Configuration,
      includeTokens: boolean = false
    ) => {
      const idTokenClaims = tokens.claims()!;

      openIdClientMock.fetchUserInfo = async () => mockUserData;
      const userinfo = await openIdClientMock.fetchUserInfo(
        oidcConfig,
        tokens.access_token,
        idTokenClaims.sub
      );

      const profile: { claims: Partial<Profile & { raw: Record<string, unknown> }> } = { claims: {} };

      profile.claims.id = idTokenClaims.sub;
      profile.claims.email = typeof idTokenClaims.email === 'string' ? idTokenClaims.email : userinfo.email;
      profile.claims.firstName =
        typeof idTokenClaims.given_name === 'string' ? idTokenClaims.given_name : userinfo.given_name;
      profile.claims.lastName =
        typeof idTokenClaims.family_name === 'string' ? idTokenClaims.family_name : userinfo.family_name;
      profile.claims.roles = idTokenClaims.roles ?? (userinfo.roles as any);
      profile.claims.groups = idTokenClaims.groups ?? (userinfo.groups as any);

      const rawClaims: Record<string, unknown> = { ...idTokenClaims, ...userinfo };

      // Include OIDC tokens as top-level SAML attributes when configured
      if (includeTokens) {
        rawClaims.id_token = tokens.id_token;
        rawClaims.access_token = tokens.access_token;
        rawClaims.refresh_token = tokens.refresh_token;
        rawClaims.token_type = tokens.token_type;
        rawClaims.expires_at = tokens.expires_at;
        rawClaims.scope = tokens.scope;
      }

      profile.claims.raw = rawClaims;
      return profile;
    },
  });

  const indexModule = tap.mockRequire('../../src/index', {
    '../../src/controller/utils': utilsMock,
  });

  const controller = await indexModule.default(jacksonOptions);

  oauthController = controller.oauthController;
  identityFederationController = controller.identityFederationController;
  connectionAPIController = controller.connectionAPIController;
});

tap.teardown(async () => {
  process.exit(0);
});

/**
 * Test: Complete SAML-OIDC Federation Flow
 *
 * Flow:
 * 1. Client sends SAML Request to Polis (Jackson)
 * 2. Polis creates OIDC Request and redirects to OIDC Provider
 * 3. OIDC Provider authenticates user and responds with tokens
 * 4. Polis creates SAML Response (with OIDC tokens if configured) and sends to Client
 */
tap.test('SAML-OIDC Federation Flow with OIDC Tokens in SAML Response', async (t) => {
  let app: IdentityFederationApp;
  let oidcConnection: OIDCSSORecord;

  t.before(async () => {
    // Create Identity Federation app with includeOidcTokensInAssertion enabled
    app = await identityFederationController.app.create({
      name: 'Test App with OIDC Tokens',
      tenant: testConfig.tenant,
      product: testConfig.product,
      entityId: testConfig.serviceProvider.entityId,
      acsUrl: testConfig.serviceProvider.acsUrl,
      includeOidcTokensInAssertion: true,
    });

    // Create OIDC connection
    oidcConnection = await connectionAPIController.createOIDCConnection(oidcConnectionConfig);
  });

  t.teardown(async () => {
    await identityFederationController.app.delete({ id: app.id });
    await connectionAPIController.deleteConnections({
      tenant: testConfig.tenant,
      product: testConfig.product,
    });
  });

  t.test('Step 1: Client sends SAML Request - Polis creates OIDC Request for IdP', async (t) => {
    const relayStateFromClient = 'client-relay-state-123';

    // Create SAML AuthnRequest from client
    const samlRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_test-request-id"
  Version="2.0"
  IssueInstant="${new Date().toISOString()}"
  AssertionConsumerServiceURL="${testConfig.serviceProvider.acsUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${testConfig.serviceProvider.entityId}</saml:Issuer>
</samlp:AuthnRequest>`;

    const encodedSamlRequest = Buffer.from(await deflateRawAsync(samlRequest)).toString('base64');

    // Client -> Polis: Send SAML Request
    const response = await identityFederationController.sso.getAuthorizeUrl({
      request: encodedSamlRequest,
      relayState: relayStateFromClient,
      samlBinding: 'HTTP-Redirect',
    });

    t.ok(response.redirect_url, 'Polis should return redirect URL to OIDC Provider');

    const oidcRequestUrl = new URL(response.redirect_url);

    // Verify OIDC request parameters
    t.ok(oidcRequestUrl.searchParams.get('state'), 'OIDC request should have state parameter');
    t.ok(oidcRequestUrl.searchParams.get('client_id'), 'OIDC request should have client_id');
    t.ok(oidcRequestUrl.searchParams.get('redirect_uri'), 'OIDC request should have redirect_uri');
    t.ok(oidcRequestUrl.searchParams.get('scope'), 'OIDC request should have scope');
    t.equal(
      oidcRequestUrl.searchParams.get('response_type'),
      'code',
      'OIDC request should use authorization code flow'
    );
    t.ok(oidcRequestUrl.searchParams.get('code_challenge'), 'OIDC request should have PKCE code_challenge');
    t.ok(oidcRequestUrl.searchParams.get('nonce'), 'OIDC request should have nonce');
  });

  t.test('Complete flow: SAML Response should contain OIDC tokens when configured', async (t) => {
    const relayStateFromClient = 'client-relay-state-with-tokens';

    // Create SAML AuthnRequest
    const samlRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_test-request-id-tokens"
  Version="2.0"
  IssueInstant="${new Date().toISOString()}"
  AssertionConsumerServiceURL="${testConfig.serviceProvider.acsUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${testConfig.serviceProvider.entityId}</saml:Issuer>
</samlp:AuthnRequest>`;

    const encodedSamlRequest = Buffer.from(await deflateRawAsync(samlRequest)).toString('base64');

    // Step 1: Client -> Polis (SAML Request)
    const authorizeResponse = await identityFederationController.sso.getAuthorizeUrl({
      request: encodedSamlRequest,
      relayState: relayStateFromClient,
      samlBinding: 'HTTP-Redirect',
    });

    const oidcRequestUrl = new URL(authorizeResponse.redirect_url);
    const polisState = oidcRequestUrl.searchParams.get('state')!;

    // Mock OIDC Provider response
    openIdClientMock.authorizationCodeGrant = async () => {
      return {
        ...mockOidcTokens,
        claims: () => ({
          ...mockUserData,
          iss: 'https://accounts.google.com',
          aud: 'test-client-id',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
        }),
      } as any;
    };

    // Step 2-3: Polis -> OIDC Provider -> Polis (token exchange)
    // Step 4: Polis -> Client (SAML Response)
    const oidcResponse = await oauthController.oidcAuthzResponse({
      code: 'mock-authorization-code',
      state: polisState,
    });

    t.ok('response_form' in oidcResponse, 'Should return SAML response form');
    t.ok(oidcResponse.response_form, 'Response form should not be empty');
    t.ok(oidcResponse.response_form?.includes('SAMLResponse'), 'Form should contain SAMLResponse');
    t.ok(oidcResponse.response_form?.includes('RelayState'), 'Form should contain RelayState');

    // Verify RelayState is preserved
    const relayStateMatch = oidcResponse.response_form?.match(
      /<input type="hidden" name="RelayState" value="([^"]+)"\/>/
    );
    t.ok(relayStateMatch, 'RelayState should be in the form');
    t.equal(
      relayStateMatch?.[1],
      relayStateFromClient,
      'RelayState should match original client relay state'
    );

    // Extract and verify SAMLResponse contains OIDC tokens
    const samlResponseMatch = oidcResponse.response_form?.match(
      /<input type="hidden" name="SAMLResponse" value="([^"]+)"\/>/
    );
    t.ok(samlResponseMatch, 'SAMLResponse should be in the form');

    if (samlResponseMatch) {
      const samlResponseXml = Buffer.from(samlResponseMatch[1], 'base64').toString('utf8');

      // Verify user attributes in SAML Response
      t.ok(samlResponseXml.includes(mockUserData.email), 'SAML Response should contain user email');

      // Verify OIDC tokens are included as separate top-level SAML attributes
      t.notOk(
        samlResponseXml.includes('oidc_tokens'),
        'SAML Response should NOT contain nested oidc_tokens attribute'
      );
      t.ok(
        samlResponseXml.includes(mockOidcTokens.access_token),
        'SAML Response should contain access_token value'
      );
      t.ok(samlResponseXml.includes(mockOidcTokens.id_token), 'SAML Response should contain id_token value');
      t.ok(
        samlResponseXml.includes(mockOidcTokens.refresh_token),
        'SAML Response should contain refresh_token value'
      );

      // Verify each token is its own saml:Attribute
      t.ok(samlResponseXml.includes('Name="id_token"'), 'SAML Response should have id_token attribute');
      t.ok(
        samlResponseXml.includes('Name="access_token"'),
        'SAML Response should have access_token attribute'
      );
      t.ok(
        samlResponseXml.includes('Name="refresh_token"'),
        'SAML Response should have refresh_token attribute'
      );
      t.ok(samlResponseXml.includes('Name="token_type"'), 'SAML Response should have token_type attribute');
    }
  });
});

tap.test('SAML Response should NOT contain OIDC tokens when not configured', async (t) => {
  let appWithoutTokens: IdentityFederationApp;
  let oidcConnection: OIDCSSORecord;

  const testConfigNoTokens = {
    tenant: 'no-tokens-tenant',
    product: 'no-tokens-product',
    serviceProvider: {
      entityId: 'https://sp-no-tokens.example.com/saml/entityId',
      acsUrl: 'https://sp-no-tokens.example.com/saml/acs',
    },
  };

  t.before(async () => {
    // Create app WITHOUT includeOidcTokensInAssertion
    appWithoutTokens = await identityFederationController.app.create({
      name: 'Test App without OIDC Tokens',
      tenant: testConfigNoTokens.tenant,
      product: testConfigNoTokens.product,
      entityId: testConfigNoTokens.serviceProvider.entityId,
      acsUrl: testConfigNoTokens.serviceProvider.acsUrl,
    });

    // Create OIDC connection
    oidcConnection = await connectionAPIController.createOIDCConnection({
      ...oidcConnectionConfig,
      tenant: testConfigNoTokens.tenant,
      product: testConfigNoTokens.product,
    });
  });

  t.teardown(async () => {
    await identityFederationController.app.delete({ id: appWithoutTokens.id });
    await connectionAPIController.deleteConnections({
      tenant: testConfigNoTokens.tenant,
      product: testConfigNoTokens.product,
    });
  });

  t.test('App created without includeOidcTokensInAssertion should have it as falsy', async (t) => {
    t.notOk(appWithoutTokens.includeOidcTokensInAssertion, 'includeOidcTokensInAssertion should be falsy');
  });

  t.test('SAML Response should not contain OIDC token attributes', async (t) => {
    const relayStateFromClient = 'client-relay-no-tokens';

    const samlRequest = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_test-no-tokens-request"
  Version="2.0"
  IssueInstant="${new Date().toISOString()}"
  AssertionConsumerServiceURL="${testConfigNoTokens.serviceProvider.acsUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${testConfigNoTokens.serviceProvider.entityId}</saml:Issuer>
</samlp:AuthnRequest>`;

    const encodedSamlRequest = Buffer.from(await deflateRawAsync(samlRequest)).toString('base64');

    const authorizeResponse = await identityFederationController.sso.getAuthorizeUrl({
      request: encodedSamlRequest,
      relayState: relayStateFromClient,
      samlBinding: 'HTTP-Redirect',
    });

    const oidcRequestUrl = new URL(authorizeResponse.redirect_url);
    const polisState = oidcRequestUrl.searchParams.get('state')!;

    // Mock OIDC Provider response (tokens will NOT be included in SAML response)
    openIdClientMock.authorizationCodeGrant = async () => {
      return {
        id_token: 'no-include-id-token',
        access_token: 'no-include-access-token',
        refresh_token: 'no-include-refresh-token',
        token_type: 'Bearer',
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        scope: 'openid profile email',
        claims: () => ({
          sub: 'user-no-tokens',
          email: 'notoken@example.com',
          given_name: 'No',
          family_name: 'Token',
          iss: 'https://accounts.google.com',
          aud: 'test-client-id',
        }),
      } as any;
    };

    const oidcResponse = await oauthController.oidcAuthzResponse({
      code: 'mock-auth-code-no-tokens',
      state: polisState,
    });

    t.ok('response_form' in oidcResponse, 'Should return SAML response form');

    const samlResponseMatch = oidcResponse.response_form?.match(
      /<input type="hidden" name="SAMLResponse" value="([^"]+)"\/>/
    );

    if (samlResponseMatch) {
      const samlResponseXml = Buffer.from(samlResponseMatch[1], 'base64').toString('utf8');

      // Verify user attributes in SAML Response
      t.ok(samlResponseXml.includes('notoken@example.com'), 'SAML Response should contain user email');

      // Verify OIDC tokens are NOT included
      t.notOk(samlResponseXml.includes('oidc_tokens'), 'SAML Response should NOT contain oidc_tokens');
      t.notOk(
        samlResponseXml.includes('no-include-access-token'),
        'SAML Response should NOT contain access_token'
      );
      t.notOk(samlResponseXml.includes('no-include-id-token'), 'SAML Response should NOT contain id_token');
    }
  });
});

tap.test('App configuration for includeOidcTokensInAssertion', async (t) => {
  let testApp: IdentityFederationApp;

  t.before(async () => {
    testApp = await identityFederationController.app.create({
      name: 'Config Test App',
      tenant: 'config-test-tenant',
      product: 'config-test-product',
      entityId: 'https://config-test.example.com/entityId',
      acsUrl: 'https://config-test.example.com/acs',
    });
  });

  t.teardown(async () => {
    await identityFederationController.app.delete({ id: testApp.id });
  });

  t.test('Should be able to enable includeOidcTokensInAssertion', async (t) => {
    const updated = await identityFederationController.app.update({
      id: testApp.id,
      includeOidcTokensInAssertion: true,
    });

    t.equal(updated.includeOidcTokensInAssertion, true, 'includeOidcTokensInAssertion should be enabled');

    const fetched = await identityFederationController.app.get({ id: testApp.id });
    t.equal(
      fetched.includeOidcTokensInAssertion,
      true,
      'Fetched app should have includeOidcTokensInAssertion enabled'
    );
  });

  t.test('Should be able to disable includeOidcTokensInAssertion', async (t) => {
    const updated = await identityFederationController.app.update({
      id: testApp.id,
      includeOidcTokensInAssertion: false,
    });

    t.equal(updated.includeOidcTokensInAssertion, false, 'includeOidcTokensInAssertion should be disabled');
  });
});
