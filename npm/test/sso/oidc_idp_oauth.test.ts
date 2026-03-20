import tap from 'tap';
import * as utils from '../../src/controller/utils';
import { IConnectionAPIController, IOAuthController, OAuthReq, Profile } from '../../src/typings';
import {
  authz_request_oidc_provider,
  GENERIC_ERR_STRING,
  oidc_response,
  oidc_response_with_error,
} from './fixture';
import { JacksonError } from '../../src/controller/error';
import { addSSOConnections, jacksonOptions } from '../utils';
import path from 'path';
import type { Configuration } from 'openid-client';

let connectionAPIController: IConnectionAPIController;
let oauthController: IOAuthController;

const metadataPath = path.join(__dirname, '/data/metadata');

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
    randomPKCECodeVerifier: () => {
      return code_verifier;
    },
    calculatePKCECodeChallenge: async () => {
      return code_challenge;
    },
  };
  utilsMock = tap.createMock(utils, {
    ...utils,
    dynamicImport: async (packageName) => {
      if (packageName === 'openid-client') {
        return openIdClientMock;
      }
      // fallback to original impl for other packages
      return utils.dynamicImport(packageName);
    },
    extractOIDCUserProfile: async (tokens: utils.AuthorizationCodeGrantResult, oidcConfig: Configuration) => {
      const idTokenClaims = tokens.claims()!;
      const client = openIdClientMock as typeof import('openid-client');
      openIdClientMock.fetchUserInfo = async () => {
        return {
          sub: 'USER_IDENTIFIER',
          email: 'jackson@example.com',
          given_name: 'jackson',
          family_name: 'samuel',
          picture: 'https://jackson.cloud.png',
          email_verified: true,
        };
      };
      const userinfo = await client.fetchUserInfo(oidcConfig, tokens.access_token, idTokenClaims.sub);

      const profile: { claims: Partial<Profile & { raw: Record<string, unknown> }> } = { claims: {} };

      profile.claims.id = idTokenClaims.sub;
      profile.claims.email = typeof idTokenClaims.email === 'string' ? idTokenClaims.email : userinfo.email;
      profile.claims.firstName =
        typeof idTokenClaims.given_name === 'string' ? idTokenClaims.given_name : userinfo.given_name;
      profile.claims.lastName =
        typeof idTokenClaims.family_name === 'string' ? idTokenClaims.family_name : userinfo.family_name;
      profile.claims.roles = idTokenClaims.roles ?? (userinfo.roles as any);
      profile.claims.groups = idTokenClaims.groups ?? (userinfo.groups as any);
      profile.claims.raw = { ...idTokenClaims, ...userinfo };

      return profile;
    },
  });

  const indexModule = tap.mockRequire('../../src/index', {
    '../../src/controller/utils': utilsMock,
  });
  const controller = await indexModule.default(jacksonOptions);

  connectionAPIController = controller.connectionAPIController;
  oauthController = controller.oauthController;
  await addSSOConnections(metadataPath, connectionAPIController);
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('[OIDCProvider]', async (t) => {
  const context: Record<string, any> = {};

  t.test('[authorize] Should return the IdP SSO URL', async (t) => {
    // will be matched in happy path test
    context.codeVerifier = code_verifier;

    const response = (await oauthController.authorize(<OAuthReq>authz_request_oidc_provider)) as {
      redirect_url: string;
    };
    const params = new URLSearchParams(new URL(response.redirect_url!).search);
    t.ok('redirect_url' in response, 'got the Idp authorize URL');
    t.ok(params.has('state'), 'state present');
    t.match(params.get('scope'), 'openid email profile', 'openid scopes present');
    t.match(params.get('code_challenge'), code_challenge, 'codeChallenge present');
    context.state = params.get('state');
  });

  t.test('[authorize] Should omit profile scope if openid.requestProfileScope is set to false', async (t) => {
    (oauthController as any).opts.openid.requestProfileScope = false;
    const response = (await oauthController.authorize(<OAuthReq>authz_request_oidc_provider)) as {
      redirect_url: string;
    };
    const params = new URLSearchParams(new URL(response.redirect_url!).search);
    t.ok('redirect_url' in response, 'got the Idp authorize URL');
    t.ok(params.has('state'), 'state present');
    t.match(params.get('scope')?.includes('profile'), false, 'profile scope should be absent');
  });

  t.test(
    '[authorize] Should include profile scope if openid.requestProfileScope is set to false but request contains scope param',
    async (t) => {
      (oauthController as any).opts.openid.requestProfileScope = false;
      const response = (await oauthController.authorize(<OAuthReq>{
        ...authz_request_oidc_provider,
        scope: 'openid email profile',
      })) as {
        redirect_url: string;
      };
      const params = new URLSearchParams(new URL(response.redirect_url!).search);
      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.ok(params.has('state'), 'state present');
      t.match(params.get('scope')?.includes('profile'), true, 'profile scope should be absent');
    }
  );

  t.test(
    '[authorize] Should not forward openid params if openid.forwardOIDCParams is set to false',
    async (t) => {
      (oauthController as any).opts.openid.forwardOIDCParams = false;
      const response = (await oauthController.authorize(<OAuthReq>{
        ...authz_request_oidc_provider,
        scope: 'openid email profile',
        prompt: 'none',
      })) as {
        redirect_url: string;
      };
      const params = new URLSearchParams(new URL(response.redirect_url!).search);
      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.match(params.has('prompt'), false, 'prompt param should be absent');
    }
  );

  t.test('[authorize] Should forward openid params if openid.forwardOIDCParams is set to true', async (t) => {
    (oauthController as any).opts.openid.forwardOIDCParams = true;
    const response = (await oauthController.authorize(<OAuthReq>{
      ...authz_request_oidc_provider,
      scope: 'openid email profile',
      prompt: 'none',
    })) as {
      redirect_url: string;
    };
    const params = new URLSearchParams(new URL(response.redirect_url!).search);
    t.ok('redirect_url' in response, 'got the Idp authorize URL');
    t.match(params.has('prompt'), true, 'prompt param should be present');
  });

  t.test('[authorize] Should return error if `oidcPath` is not set', async (t) => {
    (oauthController as any).opts.oidcPath = undefined;
    const response = (await oauthController.authorize(<OAuthReq>authz_request_oidc_provider)) as {
      redirect_url: string;
    };
    const response_params = new URLSearchParams(new URL(response.redirect_url!).search);

    t.match(response_params.get('error'), 'server_error', 'got server_error when `oidcPath` is not set');
    t.match(
      response_params.get('error_description'),
      GENERIC_ERR_STRING,
      'matched error_description when `oidcPath` is not set'
    );
    t.match(
      response_params.get('state'),
      authz_request_oidc_provider.state,
      'state present in error response'
    );
    // Restore
    (oauthController as any).opts.oidcPath = jacksonOptions.oidcPath;
  });

  t.test('[oidcAuthzResponse] Should throw an error if `state` is missing', async (t) => {
    try {
      await oauthController.oidcAuthzResponse(oidc_response);
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'State from original request is missing.', 'got expected error message');
      t.equal(statusCode, 403, 'got expected status code');
    }
  });

  t.test('[oidcAuthzResponse] Should throw an error if `state` is invalid', async (t) => {
    try {
      await oauthController.oidcAuthzResponse({ ...oidc_response, state: context.state + 'invalid_chars' });
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Unable to validate state from the original request.', 'got expected error message');
      t.equal(statusCode, 403, 'got expected status code');
    }
  });

  t.test('[oidcAuthzResponse] Should forward any provider errors to redirect_uri', async (t) => {
    const { redirect_url } = await oauthController.oidcAuthzResponse({
      ...oidc_response_with_error,
      state: context.state,
    });
    const response_params = new URLSearchParams(new URL(redirect_url!).search);

    t.match(
      response_params.get('error'),
      oidc_response_with_error.error,
      'mismatch in forwarded oidc provider error'
    );
    t.match(
      response_params.get('error_description'),
      oidc_response_with_error.error_description,
      'mismatch in forwaded oidc error_description'
    );
    t.match(
      response_params.get('state'),
      authz_request_oidc_provider.state,
      'state mismatch in error response'
    );
  });

  t.test(
    '[oidcAuthzResponse] Should return the client redirect url with code and original state attached',
    async (t) => {
      // let capturedArgs: any;
      openIdClientMock.authorizationCodeGrant = async () => {
        return {
          access_token: 'ACCESS_TOKEN',
          id_token: 'ID_TOKEN',
          token_type: 'bearer',
          claims: () => ({
            sub: 'USER_IDENTIFIER',
            email: 'jackson@example.com',
            given_name: 'jackson',
            family_name: 'samuel',
            iss: 'https://issuer.example.com',
            aud: 'https://audience.example.com',
            iat: 1643723400,
            exp: 1643727000,
          }),
        } as any;
      };

      const { redirect_url } = await oauthController.oidcAuthzResponse({
        ...oidc_response,
        state: context.state,
      });

      const response_params = new URLSearchParams(new URL(redirect_url!).search);

      t.ok(response_params.has('code'), 'code missing in redirect_url');
      t.match(response_params.get('state'), authz_request_oidc_provider.state);
    }
  );
});
