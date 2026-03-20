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
import saml from '@boxyhq/saml20';
import {
  authz_request_normal,
  authz_request_normal_oidc_flow,
  token_req_encoded_client_id,
  token_req_unencoded_client_id_gen,
  code,
  token,
  genKey,
  iv,
  clientToken,
} from './fixture';
import { addSSOConnections, jacksonOptions } from '../utils';
import type { GenerateKeyPairResult } from 'jose';

let connectionAPIController: IConnectionAPIController;
let oauthController: IOAuthController;
let keyPair: GenerateKeyPairResult;

const metadataPath = path.join(__dirname, '/data/metadata');

let connections: Array<any> = [];

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
  const jose = await import('jose');

  keyPair = await jose.generateKeyPair('RS256', { modulusLength: 3072 });

  const controller = await (
    await import('../../src/index')
  ).default({ ...jacksonOptions, flattenRawClaims: true });

  connectionAPIController = controller.connectionAPIController;
  oauthController = controller.oauthController;
  connections = await addSSOConnections(metadataPath, connectionAPIController);
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('token()', async (t) => {
  const jose = await import('jose');

  t.test(
    'Should return the tokens [id_token (if openid requested), access_token] and userprofile for a valid request',
    async (t) => {
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
        t.equal((profile as any).custom_attribute, 'custom_attribute');

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
          t.match((claims as any).custom_attribute, 'custom_attribute');
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
    }
  );
});
