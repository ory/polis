import crypto from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import sinon from 'sinon';
import tap from 'tap';
import { IConnectionAPIController, ILogoutController } from '../../src/typings';
import { relayStatePrefix } from '../../src/controller/utils';
import { saml_connection } from './fixture';
import { addSSOConnections, jacksonOptions } from '../utils';

let connectionAPIController: IConnectionAPIController;
let logoutController: ILogoutController;

const metadataPath = path.join(__dirname, '/data/metadata');

tap.before(async () => {
  const controller = await (await import('../../src/index')).default(jacksonOptions);

  connectionAPIController = controller.connectionAPIController;
  logoutController = controller.logoutController;

  await addSSOConnections(metadataPath, connectionAPIController);
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('LogoutController -> createRequest', async (t) => {
  const body = {
    nameId: 'google-oauth2|146623609101108149256',
    tenant: saml_connection.tenant,
    product: saml_connection.product,
    redirectUrl: saml_connection.defaultRedirectUrl,
  };

  t.test('createRequest', async (t) => {
    t.test('Should throw an error if the tenant or product are invalid', async (t) => {
      try {
        await logoutController.createRequest({
          ...body,
          tenant: 'invalid-tenant',
        });
      } catch (err: any) {
        t.equal(err.message, 'SAML connection not found.');
        t.equal(err.statusCode, 403);
      }

      try {
        await logoutController.createRequest({
          ...body,
          product: 'invalid-product',
        });
      } catch (err: any) {
        t.equal(err.message, 'SAML connection not found.');
        t.equal(err.statusCode, 403);
      }

      try {
        await logoutController.createRequest({
          ...body,
          tenant: '',
          product: '',
        });
      } catch (err: any) {
        t.equal(err.message, 'SAML connection not found.');
        t.equal(err.statusCode, 403);
      }
    });

    t.test("Should throw an error if metadata doesn't present SingleLogoutService URL", async (t) => {
      try {
        await logoutController.createRequest({
          ...body,
        });
      } catch (err: any) {
        t.equal(err.message, `accounts.google.com doesn't support SLO or disabled by IdP.`);
        t.equal(err.statusCode, 400);
      }
    });

    t.test('Should return logoutUrl and logoutForm for a valid logout request', async (t) => {
      const result = await logoutController.createRequest({
        ...body,
        tenant: 'example.com',
      });

      t.ok('logoutUrl' in result);
      t.ok('logoutForm' in result);
      t.ok(result.logoutUrl?.includes('https://dev-tyj7qyzz.auth0.com/samlp/logout'));

      const params = new URLSearchParams(new URL(result.logoutUrl as string).search);

      t.ok(params.has('SAMLRequest'));
      t.ok(params.has('RelayState'));
    });
  });

  t.test('handleResponse', async (t) => {
    const sessionId = 'a0089b303b86a97080ff';
    const relayState = `${relayStatePrefix}${sessionId}`;

    const logoutResponseXML = await fs.readFile(path.join(__dirname, '/data/logout_response.xml'), 'utf8');
    const logoutResponseFailedXML = await fs.readFile(
      path.join(__dirname, '/data/logout_response_failed.xml'),
      'utf8'
    );

    const logoutResponse = Buffer.from(logoutResponseXML).toString('base64');
    const logoutResponseFailed = Buffer.from(logoutResponseFailedXML).toString('base64');

    sinon.stub(crypto, 'randomBytes').returns(sessionId as any);

    await logoutController.createRequest({
      ...body,
      tenant: 'example.com',
    });

    t.test('Should throw an error is RelayState is invalid', async (t) => {
      try {
        await logoutController.handleResponse({
          SAMLResponse: logoutResponse,
          RelayState: 'invalid',
        });
      } catch (err: any) {
        t.equal(err.message, 'Unable to validate state from the origin request.');
        t.equal(err.statusCode, 403);
      }
    });

    t.test('Should throw an error is logout request not success', async (t) => {
      try {
        await logoutController.handleResponse({
          SAMLResponse: logoutResponseFailed,
          RelayState: relayState,
        });
      } catch (err: any) {
        t.equal(err.message, 'SLO failed with status urn:oasis:names:tc:SAML:2.0:status:AuthnFailed.');
        t.equal(err.statusCode, 400);
      }
    });

    t.test('Should throw an error when request ID mismatch', async (t) => {
      const logoutResponse = Buffer.from(logoutResponseXML.replace(`_${sessionId}`, '_123')).toString(
        'base64'
      );

      try {
        await logoutController.handleResponse({
          SAMLResponse: logoutResponse,
          RelayState: relayState,
        });
      } catch (err: any) {
        t.equal(err.message, 'SLO failed with mismatched request ID.');
        t.equal(err.statusCode, 400);
      }
    });

    t.test('Return the redirectUrl after the post logout', async (t) => {
      const result = await logoutController.handleResponse({
        SAMLResponse: logoutResponse,
        RelayState: relayState,
      });

      t.ok('redirectUrl' in result);
      t.match(result.redirectUrl, saml_connection.defaultRedirectUrl);
    });
  });
});
