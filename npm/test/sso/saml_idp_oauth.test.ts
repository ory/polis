import crypto from 'crypto';
import { promises as fs } from 'fs';
import * as utils from '../../src/controller/utils';
import path from 'path';
import {
  IOAuthController,
  IConnectionAPIController,
  OAuthTokenReq,
  SAMLResponsePayload,
  OAuthReq,
} from '../../src/typings';
import sinon from 'sinon';
import tap from 'tap';
import { JacksonError } from '../../src/controller/error';
import saml from '@boxyhq/saml20';
import {
  authz_request_normal,
  authz_request_with_forceauthn,
  authz_request_normal_oidc_flow,
  authz_request_normal_with_access_type,
  authz_request_normal_with_code_challenge,
  authz_request_normal_with_resource,
  authz_request_normal_with_scope,
  bodyWithDummyCredentials,
  bodyWithInvalidClientSecret,
  bodyWithInvalidCode,
  bodyWithInvalidRedirectUri,
  bodyWithMissingRedirectUri,
  bodyWithUnencodedClientId_InvalidClientSecret_gen,
  invalid_client_id,
  invalid_tenant_product,
  redirect_uri_not_allowed,
  redirect_uri_not_set,
  response_type_not_code,
  state_not_set,
  token_req_encoded_client_id,
  token_req_dummy_client_id_idp_saml_login,
  token_req_unencoded_client_id_gen,
  token_req,
  token_req_encoded_client_id_idp_saml_login,
  token_req_dummy_client_id_idp_saml_login_wrong_secretverifier,
  token_req_encoded_client_id_idp_saml_login_wrong_secretverifier,
  code,
  token,
  genKey,
  iv,
  clientCode,
  clientToken,
  GENERIC_ERR_STRING,
} from './fixture';
import { addSSOConnections, jacksonOptions } from '../utils';
import boxyhq from './data/metadata/boxyhq';
import type { GenerateKeyPairResult } from 'jose';

let connectionAPIController: IConnectionAPIController;
let oauthController: IOAuthController;
let idpEnabledConnectionAPIController: IConnectionAPIController; //idp initiated saml flow enabled
let idpEnabledOAuthController: IOAuthController;
let keyPair: GenerateKeyPairResult;

const metadataPath = path.join(__dirname, '/data/metadata');

let connections: Array<any> = [];
let code_verifier: string;
let code_challenge: string;

function _stubRandomBytes(codeOrToken: string) {
  return sinon
    .stub(crypto, 'randomBytes')
    .returns(codeOrToken as any)
    .onSecondCall()
    .returns(genKey as any)
    .onThirdCall()
    .returns(iv as any);
}

function stubRandomBytesCode() {
  return _stubRandomBytes(code);
}

function stubRandomBytesToken() {
  return _stubRandomBytes(token);
}

function stubRandomBytesAll() {
  return sinon
    .stub(crypto, 'randomBytes')
    .returns(code as any)
    .onSecondCall()
    .returns(genKey as any)
    .onThirdCall()
    .returns(iv as any)
    .onCall(3)
    .returns(token as any)
    .onCall(4)
    .returns(genKey as any)
    .onCall(5)
    .returns(iv as any);
}

tap.before(async () => {
  const client = await import('openid-client');
  const jose = await import('jose');
  code_verifier = client.randomPKCECodeVerifier();
  code_challenge = await client.calculatePKCECodeChallenge(code_verifier);

  keyPair = await jose.generateKeyPair('RS256', { modulusLength: 3072 });

  const controller = await (await import('../../src/index')).default(jacksonOptions);
  const idpFlowEnabledController = await (
    await import('../../src/index')
  ).default({ ...jacksonOptions, idpEnabled: true });

  connectionAPIController = controller.connectionAPIController;
  oauthController = controller.oauthController;
  idpEnabledConnectionAPIController = idpFlowEnabledController.connectionAPIController;
  idpEnabledOAuthController = idpFlowEnabledController.oauthController;
  connections = await addSSOConnections(
    metadataPath,
    connectionAPIController,
    idpEnabledConnectionAPIController
  );
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('authorize()', async (t) => {
  t.test('Should throw an error if `redirect_uri` null', async (t) => {
    const body = redirect_uri_not_set;

    try {
      await oauthController.authorize(<OAuthReq>body);
      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Please specify a redirect URL.', 'got expected error message');
      t.equal(statusCode, 400, 'got expected status code');
    }
  });

  t.test('Should return OAuth Error response if `state` is not set', async (t) => {
    const body = state_not_set;

    const { redirect_url } = (await oauthController.authorize(<OAuthReq>body)) as {
      redirect_url: string;
    };
    // should contain traceId in error_description
    t.match(
      redirect_url,
      new RegExp(
        `${body.redirect_uri}\\?error=invalid_request&error_description=[a-z]+_[a-z]+_[a-z]+%3A\\+Please\\+specify\\+a\\+state\\+to\\+safeguard\\+against\\+XSRF\\+attacks`
      ),
      'got OAuth error'
    );
  });

  t.test('Should return OAuth Error response if `response_type` is not `code`', async (t) => {
    const body = response_type_not_code;

    const { redirect_url } = (await oauthController.authorize(<OAuthReq>body)) as {
      redirect_url: string;
    };
    // should contain traceId in error_description
    t.match(
      redirect_url,
      new RegExp(
        `${body.redirect_uri}\\?error=unsupported_response_type&error_description=[a-z]+_[a-z]+_[a-z]+%3A\\+Only\\+Authorization\\+Code\\+grant\\+is\\+supported&state=${body.state}`
      ),
      'got OAuth error'
    );
  });

  t.test('Should return OAuth Error response if request creation fails', async (t) => {
    const body = authz_request_normal;
    const stubSamlRequest = sinon.stub(saml, 'request').throws(Error('Internal error: Fatal'));
    const { redirect_url } = (await oauthController.authorize(<OAuthReq>body)) as {
      redirect_url: string;
    };
    // should contain traceId in error_description
    t.match(
      redirect_url,
      new RegExp(
        `${body.redirect_uri}\\?error=server_error&error_description=[a-z]+_[a-z]+_[a-z]+%3A\\+Internal\\+error%3A\\+Fatal&state=${body.state}`
      ),
      'got OAuth error'
    );
    stubSamlRequest.restore();
  });

  t.test('Should throw an error if `client_id` is invalid', async (t) => {
    const body = invalid_client_id;

    try {
      await oauthController.authorize(<OAuthReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, GENERIC_ERR_STRING, 'got expected error message');
      t.equal(statusCode, 403, 'got expected status code');
    }
  });

  t.test('Should throw an error if `redirect_uri` is not allowed', async (t) => {
    const body = redirect_uri_not_allowed;

    try {
      await oauthController.authorize(<OAuthReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Redirect URL is not allowed.', 'got expected error message');
      t.equal(statusCode, 403, 'got expected status code');
    }
  });

  t.test('Should return the Idp SSO URL', async (t) => {
    t.test('accepts client_id', async (t) => {
      const body = authz_request_normal;

      const response = (await oauthController.authorize(<OAuthReq>body)) as {
        redirect_url: string;
      };
      const params = new URLSearchParams(new URL(response.redirect_url!).search);

      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.ok(params.has('RelayState'), 'RelayState present in the query string');
      t.ok(params.has('SAMLRequest'), 'SAMLRequest present in the query string');
    });

    t.test('accepts single value in prompt', async (t) => {
      const body = authz_request_with_forceauthn;

      const response = await oauthController.authorize(<OAuthReq>body);
      const params = new URLSearchParams(new URL(response.redirect_url!).search);

      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.ok(params.has('RelayState'), 'RelayState present in the query string');
      t.ok(params.has('SAMLRequest'), 'SAMLRequest present in the query string');
    });

    t.test('accepts access_type', async (t) => {
      const body = authz_request_normal_with_access_type;

      const response = (await oauthController.authorize(<OAuthReq>body)) as {
        redirect_url: string;
      };
      const params = new URLSearchParams(new URL(response.redirect_url!).search);

      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.ok(params.has('RelayState'), 'RelayState present in the query string');
      t.ok(params.has('SAMLRequest'), 'SAMLRequest present in the query string');
    });

    t.test('accepts resource', async (t) => {
      const body = authz_request_normal_with_resource;

      const response = (await oauthController.authorize(<OAuthReq>body)) as {
        redirect_url: string;
      };
      const params = new URLSearchParams(new URL(response.redirect_url!).search);

      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.ok(params.has('RelayState'), 'RelayState present in the query string');
      t.ok(params.has('SAMLRequest'), 'SAMLRequest present in the query string');
    });

    t.test('accepts scope', async (t) => {
      const body = authz_request_normal_with_scope;

      const response = (await oauthController.authorize(<OAuthReq>body)) as {
        redirect_url: string;
      };
      const params = new URLSearchParams(new URL(response.redirect_url!).search);

      t.ok('redirect_url' in response, 'got the Idp authorize URL');
      t.ok(params.has('RelayState'), 'RelayState present in the query string');
      t.ok(params.has('SAMLRequest'), 'SAMLRequest present in the query string');
    });
  });
});

tap.test('samlResponse()', async (t) => {
  const authBody = authz_request_normal;

  const { redirect_url } = (await oauthController.authorize(<OAuthReq>authBody)) as {
    redirect_url: string;
  };

  const relayState = new URLSearchParams(new URL(redirect_url!).search).get('RelayState');

  const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');

  t.test('Should throw an error if `RelayState` is missing', async (t) => {
    const responseBody: Partial<SAMLResponsePayload> = {
      SAMLResponse: rawResponse,
    };

    try {
      await oauthController.samlResponse(<SAMLResponsePayload>responseBody);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, GENERIC_ERR_STRING, 'got expected error message');

      t.equal(statusCode, 403, 'got expected status code');
    }
  });

  t.test('Should return OAuth Error response if response validation fails', async (t) => {
    const responseBody = {
      SAMLResponse: rawResponse,
      RelayState: relayState,
    };

    const stubValidate = sinon.stub(saml, 'validate').throws(Error('Internal error: Fatal'));

    const response = await oauthController.samlResponse(<SAMLResponsePayload>responseBody);

    const params = new URLSearchParams(new URL(response.redirect_url!).search);
    t.match(params.get('error'), 'access_denied');
    t.match(params.get('error_description'), 'Internal error: Fatal');

    stubValidate.restore();
  });

  t.test('Should return a URL with code and state as query params', async (t) => {
    const responseBody = {
      SAMLResponse: rawResponse,
      RelayState: relayState,
    };

    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: '',
      claims: {
        id: '123',
      },
      issuer: '',
      sessionIndex: '',
    });

    const stubRandomBytes = stubRandomBytesCode();

    const response = await oauthController.samlResponse(<SAMLResponsePayload>responseBody);

    const params = new URLSearchParams(new URL(response.redirect_url!).search);

    t.ok(stubValidate.calledOnce, 'validate called once');
    t.ok(
      stubRandomBytes.calledThrice,
      'samlResponse randomBytes called thrice: ' + stubRandomBytes.callCount
    );
    t.ok('redirect_url' in response, 'response contains redirect_url');
    t.ok(params.has('code'), 'query string includes code');
    t.ok(params.has('state'), 'query string includes state');
    t.match(params.get('state'), authBody.state, 'state value is valid');

    stubRandomBytes.restore();
    stubValidate.restore();
  });
});

tap.test('token()', async (t) => {
  const jose = await import('jose');
  t.test('Should throw an error if `grant_type` is not `authorization_code`', async (t) => {
    const body = {
      grant_type: 'authorization_code_1',
    };

    try {
      await oauthController.token(<OAuthTokenReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Unsupported grant_type', 'got expected error message');
      t.equal(statusCode, 400, 'got expected status code');
    }
  });

  t.test('Should throw an error if `tenant` is invalid', async (t) => {
    const body = invalid_tenant_product(undefined, 'invalidTenant');

    try {
      await oauthController.token(<OAuthTokenReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid tenant or product');
      t.equal(statusCode, 401, 'got expected status code');
    }
  });

  t.test('Should throw an error if `product` is invalid', async (t) => {
    const body = invalid_tenant_product('invalidProduct');

    try {
      await oauthController.token(<OAuthTokenReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid tenant or product');
      t.equal(statusCode, 401, 'got expected status code');
    }
  });

  t.test('Should throw an error if `tenant` and `product` is invalid', async (t) => {
    const body = invalid_tenant_product('invalidProduct', 'invalidTenant');

    try {
      await oauthController.token(<OAuthTokenReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid tenant or product');
      t.equal(statusCode, 401, 'got expected status code');
    }
  });

  t.test('Should throw an error if `code` is missing', async (t) => {
    const body = {
      grant_type: 'authorization_code',
    };

    try {
      await oauthController.token(<OAuthTokenReq>body);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Please specify code', 'got expected error message');
      t.equal(statusCode, 400, 'got expected status code');
    }
  });

  t.test('Should throw an error if `code` or `client_secret` is invalid', async (t) => {
    try {
      await oauthController.token(<OAuthTokenReq>bodyWithInvalidCode);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid code', 'got expected error message');
      t.equal(statusCode, 403, 'got expected status code');
    }

    try {
      await oauthController.token(<OAuthTokenReq>bodyWithInvalidRedirectUri);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid request: redirect_uri mismatch', 'got expected error message');
      t.equal(statusCode, 400, 'got expected status code');
    }

    try {
      await oauthController.token(<OAuthTokenReq>bodyWithMissingRedirectUri);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid request: redirect_uri missing', 'got expected error message');
      t.equal(statusCode, 400, 'got expected status code');
    }

    try {
      await oauthController.token(<OAuthTokenReq>bodyWithInvalidClientSecret);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid client_secret', 'got expected error message');
      t.equal(statusCode, 401, 'got expected status code');
    }

    try {
      const bodyWithUnencodedClientId_InvalidClientSecret =
        bodyWithUnencodedClientId_InvalidClientSecret_gen(connections);
      await oauthController.token(<OAuthTokenReq>bodyWithUnencodedClientId_InvalidClientSecret);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid client_id or client_secret', 'got expected error message');
      t.equal(statusCode, 401, 'got expected status code');
    }

    try {
      await oauthController.token(<OAuthTokenReq>bodyWithDummyCredentials);

      t.fail('Expecting JacksonError.');
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid client_secret', 'got expected error message');
      t.equal(statusCode, 401, 'got expected status code');
    }
  });

  t.test(
    'Should return the tokens [id_token (if openid requested), access_token] and userprofile for a valid request',
    async (t) => {
      t.test('encoded client_id', async (t) => {
        const body = token_req_encoded_client_id;
        const stubRandomBytes = stubRandomBytesToken();

        const response = await oauthController.token(<OAuthTokenReq>body);

        t.ok(stubRandomBytes.calledThrice, 'token randomBytes called thrice: ' + stubRandomBytes.callCount);
        t.ok('access_token' in response, 'includes access_token');
        t.ok('token_type' in response, 'includes token_type');
        t.ok('expires_in' in response, 'includes expires_in');
        t.notOk('id_token' in response, 'does not include id_token');
        t.match(response.access_token, clientToken);
        t.match(response.token_type, 'bearer');
        t.match(response.expires_in, 300);

        stubRandomBytes.restore();
      });

      t.test('unencoded client_id', async (t) => {
        // have to call authorize, because previous happy path deletes the code.
        const authBody = authz_request_normal;

        const { redirect_url } = (await oauthController.authorize(<OAuthReq>authBody)) as {
          redirect_url: string;
        };

        const relayState = new URLSearchParams(new URL(redirect_url!).search).get('RelayState');

        const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
        const responseBody = {
          SAMLResponse: rawResponse,
          RelayState: relayState,
        };

        const stubValidate = sinon.stub(saml, 'validate').resolves({
          audience: '',
          claims: {
            id: '123',
            custom_attribute: 'custom_attribute',
          },
          issuer: '',
          sessionIndex: '',
        });

        const stubRandomBytes = stubRandomBytesAll();

        await oauthController.samlResponse(<SAMLResponsePayload>responseBody);

        const body = token_req_unencoded_client_id_gen(connections);

        const tokenRes = await oauthController.token(<OAuthTokenReq>body);

        t.ok('access_token' in tokenRes, 'includes access_token');
        t.ok('token_type' in tokenRes, 'includes token_type');
        t.ok('expires_in' in tokenRes, 'includes expires_in');
        t.notOk('id_token' in tokenRes, 'does not include id_token');
        t.match(tokenRes.access_token, clientToken);
        t.match(tokenRes.token_type, 'bearer');
        t.match(tokenRes.expires_in, 300);

        const profile = await oauthController.userInfo(tokenRes.access_token);

        t.notOk('sub' in profile, 'does not include sub');
        t.equal(profile.requested.client_id, authz_request_normal.client_id);
        t.equal(profile.requested.state, authz_request_normal.state);
        t.equal(profile.requested.tenant, new URLSearchParams(authz_request_normal.client_id).get('tenant'));
        t.equal(
          profile.requested.product,
          new URLSearchParams(authz_request_normal.client_id).get('product')
        );
        t.equal(profile.raw.custom_attribute, 'custom_attribute');

        stubRandomBytes.restore();
        stubValidate.restore();
      });

      t.test('openid flow', async (t) => {
        const authBody = authz_request_normal_oidc_flow;

        const { redirect_url } = (await oauthController.authorize(<OAuthReq>authBody)) as {
          redirect_url: string;
        };

        const relayState = new URLSearchParams(new URL(redirect_url!).search).get('RelayState');

        const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
        const responseBody = {
          SAMLResponse: rawResponse,
          RelayState: relayState,
        };

        const stubLoadJWSPrivateKey = sinon.stub(utils, 'loadJWSPrivateKey').resolves(keyPair.privateKey);
        const stubimportJWTPublicKey = sinon.stub(utils, 'importJWTPublicKey').resolves(keyPair.publicKey);
        const stubValidate = sinon.stub(saml, 'validate').resolves({
          audience: '',
          claims: {
            id: 'id',
            firstName: 'john',
            lastName: 'doe',
            email: 'johndoe@example.com',
            custom_attribute: 'custom_attribute',
          },
          issuer: '',
          sessionIndex: '',
        });

        const stubRandomBytes = stubRandomBytesAll();

        await oauthController.samlResponse(<SAMLResponsePayload>responseBody);

        const body = token_req_encoded_client_id;

        const tokenRes = await oauthController.token(<OAuthTokenReq>body);

        t.ok('access_token' in tokenRes, 'includes access_token');
        t.ok('token_type' in tokenRes, 'includes token_type');
        t.ok('expires_in' in tokenRes, 'includes expires_in');
        t.ok('id_token' in tokenRes, 'includes id_token');
        if (tokenRes.id_token) {
          const claims = jose.decodeJwt(tokenRes.id_token);
          const { protectedHeader } = await jose.jwtVerify(tokenRes.id_token, keyPair.publicKey);
          t.match(protectedHeader.alg, jacksonOptions.openid?.jwsAlg);
          t.match(claims.aud, authz_request_normal_oidc_flow.client_id);
          t.match(claims.iss, jacksonOptions.externalUrl);
          t.match((claims as any).raw.custom_attribute, 'custom_attribute');
        }
        t.match(tokenRes.access_token, token);
        t.match(tokenRes.token_type, 'bearer');
        t.match(tokenRes.expires_in, 300);

        const profile = await oauthController.userInfo(tokenRes.access_token);

        t.equal(profile.sub, 'id');
        t.equal(profile.requested.client_id, authz_request_normal_oidc_flow.client_id);
        t.equal(profile.requested.state, authz_request_normal_oidc_flow.state);
        t.equal(
          profile.requested.tenant,
          new URLSearchParams(authz_request_normal_oidc_flow.client_id).get('tenant')
        );
        t.equal(
          profile.requested.product,
          new URLSearchParams(authz_request_normal_oidc_flow.client_id).get('product')
        );

        stubRandomBytes.restore();
        stubValidate.restore();
        stubLoadJWSPrivateKey.restore();
        stubimportJWTPublicKey.restore();
      });

      t.test('PKCE check', async (t) => {
        const authBody = authz_request_normal_with_code_challenge;
        authBody.code_challenge = code_challenge;

        const { redirect_url } = (await oauthController.authorize(<OAuthReq>authBody)) as {
          redirect_url: string;
        };

        const relayState = new URLSearchParams(new URL(redirect_url!).search).get('RelayState');

        const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
        const responseBody = {
          SAMLResponse: rawResponse,
          RelayState: relayState,
        };

        // const stubLoadJWSPrivateKey = sinon.stub(utils, 'loadJWSPrivateKey').resolves(keyPair.privateKey);
        const stubValidate = sinon.stub(saml, 'validate').resolves({
          audience: '',
          claims: { id: 'id', firstName: 'john', lastName: 'doe', email: 'johndoe@example.com' },
          issuer: '',
          sessionIndex: '',
        });

        const stubRandomBytes = stubRandomBytesAll();

        await oauthController.samlResponse(<SAMLResponsePayload>responseBody);

        try {
          await oauthController.token(<OAuthTokenReq>{
            ...token_req,
            code_verifier: code_verifier + 'invalid_chars',
          });
          t.fail('Expecting JacksonError.');
        } catch (err) {
          const { message, statusCode } = err as JacksonError;
          t.equal(message, 'Invalid code_verifier', 'got expected error message');
          t.equal(statusCode, 401, 'got expected status code');
        }

        const tokenRes = await oauthController.token(<OAuthTokenReq>{ ...token_req, code_verifier });

        t.ok('access_token' in tokenRes, 'includes access_token');
        t.ok('token_type' in tokenRes, 'includes token_type');
        t.ok('expires_in' in tokenRes, 'includes expires_in');
        t.match(tokenRes.access_token, token);
        t.match(tokenRes.token_type, 'bearer');
        t.match(tokenRes.expires_in, 300);

        const profile = await oauthController.userInfo(tokenRes.access_token);
        t.equal(profile.requested.client_id, authz_request_normal_with_code_challenge.client_id);
        t.equal(profile.requested.state, authz_request_normal_with_code_challenge.state);
        t.equal(
          profile.requested.tenant,
          new URLSearchParams(authz_request_normal_with_code_challenge.client_id).get('tenant')
        );
        t.equal(
          profile.requested.product,
          new URLSearchParams(authz_request_normal_with_code_challenge.client_id).get('product')
        );

        stubRandomBytes.restore();
        stubValidate.restore();
      });
    }
  );
});

tap.test('IdP initiated flow', async (t) => {
  t.test('authentication should fail with encoded client_id and wrong client_secret_verifier', async (t) => {
    const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
    const responseBody = {
      SAMLResponse: rawResponse,
    };
    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: '',
      claims: { id: 'id', firstName: 'john', lastName: 'doe', email: 'johndoe@example.com' },
      issuer: '',
      sessionIndex: '',
    });

    const stubRandomBytes = stubRandomBytesAll();

    const { redirect_url } = await idpEnabledOAuthController.samlResponse(<SAMLResponsePayload>responseBody);
    t.equal(new URLSearchParams(new URL(redirect_url!).search).get('code'), clientCode);

    const body = token_req_encoded_client_id_idp_saml_login_wrong_secretverifier;

    try {
      await idpEnabledOAuthController.token(<OAuthTokenReq>body);
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid client_secret', 'got expected error message');
      t.equal(statusCode, 401, 'got expected status code');
    }

    stubRandomBytes.restore();
    stubValidate.restore();
  });

  t.test('authentication should fail with dummy client_id and wrong client_secret_verifier', async (t) => {
    const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
    const responseBody = {
      SAMLResponse: rawResponse,
    };
    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: '',
      claims: { id: 'id', firstName: 'john', lastName: 'doe', email: 'johndoe@example.com' },
      issuer: '',
      sessionIndex: '',
    });

    const stubRandomBytes = stubRandomBytesAll();

    const { redirect_url } = await idpEnabledOAuthController.samlResponse(<SAMLResponsePayload>responseBody);
    t.equal(new URLSearchParams(new URL(redirect_url!).search).get('code'), clientCode);

    const body = token_req_dummy_client_id_idp_saml_login_wrong_secretverifier;

    try {
      await idpEnabledOAuthController.token(<OAuthTokenReq>body);
    } catch (err) {
      const { message, statusCode } = err as JacksonError;
      t.equal(message, 'Invalid client_secret', 'got expected error message');
      t.equal(statusCode, 401, 'got expected status code');
    }

    stubRandomBytes.restore();
    stubValidate.restore();
  });

  t.test('authentication should succeed with encoded client_id and client_secret_verifier', async (t) => {
    const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
    const responseBody = {
      SAMLResponse: rawResponse,
    };
    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: '',
      claims: { id: 'id', firstName: 'john', lastName: 'doe', email: 'johndoe@example.com' },
      issuer: '',
      sessionIndex: '',
    });

    const stubRandomBytes = stubRandomBytesAll();

    const { redirect_url } = await idpEnabledOAuthController.samlResponse(<SAMLResponsePayload>responseBody);
    t.equal(new URLSearchParams(new URL(redirect_url!).search).get('code'), clientCode);

    const body = token_req_encoded_client_id_idp_saml_login;

    const tokenRes = await idpEnabledOAuthController.token(<OAuthTokenReq>body);
    t.ok('access_token' in tokenRes, 'includes access_token');
    t.ok('token_type' in tokenRes, 'includes token_type');
    t.ok('expires_in' in tokenRes, 'includes expires_in');
    t.equal(tokenRes.access_token, clientToken);
    t.equal(tokenRes.token_type, 'bearer');
    t.equal(tokenRes.expires_in, 300);
    const profile = await idpEnabledOAuthController.userInfo(tokenRes.access_token);

    t.equal(profile.id, 'id');
    t.equal(profile.requested.tenant, boxyhq.tenant);
    t.equal(profile.requested.product, boxyhq.product);
    t.equal(profile.requested.isIdPFlow, true);
    stubRandomBytes.restore();
    stubValidate.restore();
  });

  t.test('authentication should succeed with dummy client_id and client_secret_verifier', async (t) => {
    const rawResponse = await fs.readFile(path.join(__dirname, '/data/saml_response'), 'utf8');
    const responseBody = {
      SAMLResponse: rawResponse,
    };
    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: '',
      claims: { id: 'id', firstName: 'john', lastName: 'doe', email: 'johndoe@example.com' },
      issuer: '',
      sessionIndex: '',
    });

    const stubRandomBytes = stubRandomBytesAll();

    const { redirect_url } = await idpEnabledOAuthController.samlResponse(<SAMLResponsePayload>responseBody);
    t.equal(new URLSearchParams(new URL(redirect_url!).search).get('code'), clientCode);

    const body = token_req_dummy_client_id_idp_saml_login;

    const tokenRes = await idpEnabledOAuthController.token(<OAuthTokenReq>body);
    t.ok('access_token' in tokenRes, 'includes access_token');
    t.ok('token_type' in tokenRes, 'includes token_type');
    t.ok('expires_in' in tokenRes, 'includes expires_in');
    t.equal(tokenRes.access_token, clientToken);
    t.equal(tokenRes.token_type, 'bearer');
    t.equal(tokenRes.expires_in, 300);
    const profile = await idpEnabledOAuthController.userInfo(tokenRes.access_token);

    t.equal(profile.id, 'id');
    t.equal(profile.requested.tenant, boxyhq.tenant);
    t.equal(profile.requested.product, boxyhq.product);
    t.equal(profile.requested.isIdPFlow, true);
    stubRandomBytes.restore();
    stubValidate.restore();
  });
});
