import tap from 'tap';
import path from 'path';
import sinon from 'sinon';
import { promisify } from 'util';
import { deflateRaw } from 'zlib';
import saml from '@boxyhq/saml20';
import { promises as fs } from 'fs';

const deflateRawAsync = promisify(deflateRaw);

import { jacksonOptions } from '../utils';
import { tenant, product, serviceProvider } from './constants';
import type {
  IIdentityFederationController,
  IConnectionAPIController,
  IOAuthController,
  IdentityFederationApp,
  SAMLSSORecord,
} from '../../src';

let oauthController: IOAuthController;
let identityFederationController: IIdentityFederationController;
let connectionAPIController: IConnectionAPIController;

let app: IdentityFederationApp;
let connection: SAMLSSORecord;

tap.before(async () => {
  const jackson = await (await import('../../src/index')).default(jacksonOptions);

  oauthController = jackson.oauthController;
  identityFederationController = jackson.identityFederationController;
  connectionAPIController = jackson.connectionAPIController;

  // Create app
  app = await identityFederationController.app.create({
    name: 'Test App',
    tenant,
    product,
    entityId: serviceProvider.entityId,
    acsUrl: serviceProvider.acsUrl,
  });

  // Create SAML connection
  connection = await connectionAPIController.createSAMLConnection({
    tenant,
    product,
    rawMetadata: await fs.readFile(path.join(__dirname, '/data/metadata.xml'), 'utf8'),
    defaultRedirectUrl: 'http://localhost:3366/sso/callback',
    redirectUrl: '["http://localhost:3366"]',
  });
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('Federated SAML flow', async (t) => {
  t.teardown(async () => {
    await identityFederationController.app.delete({ id: app.id });
    await connectionAPIController.deleteConnections({ tenant, product });
  });

  t.test('Federated SAML flow without ttlInMinutes', async (t) => {
    const relayStateFromSP = 'sp-saml-request-relay-state';

    const requestXML = await fs.readFile(path.join(__dirname, '/data/request.xml'), 'utf8');
    const responseXML = await fs.readFile(path.join(__dirname, '/data/response.xml'), 'utf8');

    const samlRequestFromSP = Buffer.from(await deflateRawAsync(requestXML)).toString('base64');
    const samlResponseFromIdP = Buffer.from(responseXML).toString('base64');

    let jacksonRelayState: string | null = null;

    t.test('Should be able to accept SAML Request from SP and generate SAML Request for IdP', async (t) => {
      const response = await identityFederationController.sso.getAuthorizeUrl({
        request: samlRequestFromSP,
        relayState: relayStateFromSP,
        samlBinding: 'HTTP-Redirect',
      });

      // Extract relay state created by Jackson
      jacksonRelayState = new URL(response.redirect_url).searchParams.get('RelayState');

      t.ok(
        response.redirect_url?.startsWith(`${connection.idpMetadata.sso.redirectUrl}`),
        'Should have a SSO URL that starts with IdP SSO URL'
      );
      t.ok(response.redirect_url, 'Should have a redirect URL');
      t.ok(response.redirect_url?.includes('SAMLRequest'), 'Should have a SAMLRequest in the redirect URL');
      t.ok(response.redirect_url?.includes('RelayState'), 'Should have a RelayState in the redirect URL');
    });

    t.test('Should be able to accept SAML Response from IdP and generate SAML Response for SP', async (t) => {
      const stubValidate = sinon.stub(saml, 'validate').resolves({
        audience: 'https://saml.boxyhq.com',
        claims: {
          id: '00u3e3cmpdDydXdzV5d7',
          email: 'kiran@boxyhq.com',
          firstName: 'Kiran',
          lastName: 'Krishnan',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': 'kiran@boxyhq.com',
        },
        issuer: 'https://saml.example.com/entityid',
        sessionIndex: '_a30730c45288bbc4986b',
      });

      const response = await oauthController.samlResponse({
        SAMLResponse: samlResponseFromIdP,
        RelayState: jacksonRelayState ?? '',
      });

      t.ok(response);
      t.ok('response_form' in response);
      t.ok(
        response.response_form?.includes('SAMLResponse'),
        'Should have a SAMLResponse in the response form'
      );
      t.ok(response.response_form?.includes('RelayState'), 'Should have a RelayState in the response form');

      const relayState = response.response_form
        ? response.response_form.match(/<input type="hidden" name="RelayState" value="(.*)"\/>/)?.[1]
        : null;

      t.match(relayState, relayStateFromSP, 'Should have the same relay state as the one sent by SP');

      stubValidate.restore();
    });
  });
});

tap.test('Federated SAML flow with ttlInMinutes', async (t) => {
  const ttlTenant = 'boxyhq-ttl';
  const ttlProduct = 'flex-ttl';
  // Use the same acsUrl/entityId as in request.xml to avoid ACS URL mismatch
  const ttlServiceProvider = {
    acsUrl: 'https://twilio.com/saml2/acs',
    entityId: 'https://twilio.com/saml2/entityId/ttl',
  };

  let appWithTtl: IdentityFederationApp;

  t.before(async () => {
    // Create app with ttlInMinutes configured
    // Note: Using 'as any' because ttlInMinutes should be added to NewAppParams type
    appWithTtl = await identityFederationController.app.create({
      name: 'Test App with TTL',
      tenant: ttlTenant,
      product: ttlProduct,
      entityId: ttlServiceProvider.entityId,
      acsUrl: ttlServiceProvider.acsUrl,
      ttlInMinutes: 30,
    } as any);

    // Create SAML connection for the TTL test
    await connectionAPIController.createSAMLConnection({
      tenant: ttlTenant,
      product: ttlProduct,
      rawMetadata: await fs.readFile(path.join(__dirname, '/data/metadata.xml'), 'utf8'),
      defaultRedirectUrl: 'http://localhost:3366/sso/callback',
      redirectUrl: '["http://localhost:3366"]',
    });
  });

  t.teardown(async () => {
    await identityFederationController.app.delete({ id: appWithTtl.id });
    await connectionAPIController.deleteConnections({ tenant: ttlTenant, product: ttlProduct });
  });

  t.test('App should be created with ttlInMinutes', async (t) => {
    t.equal(appWithTtl.ttlInMinutes, 30, 'App should have ttlInMinutes set to 30');
  });

  t.test('SAML Response should include ttlInMinutes when configured', async (t) => {
    const relayStateFromSP = 'sp-saml-request-relay-state-ttl';

    // Read SAML request/response - use original request.xml values (entityId must match app's entityId)
    const requestXML = (await fs.readFile(path.join(__dirname, '/data/request.xml'), 'utf8')).replace(
      'https://twilio.com/saml2/entityId',
      ttlServiceProvider.entityId
    );
    const responseXML = await fs.readFile(path.join(__dirname, '/data/response.xml'), 'utf8');

    const samlRequestFromSP = Buffer.from(await deflateRawAsync(requestXML)).toString('base64');
    const samlResponseFromIdP = Buffer.from(responseXML).toString('base64');

    // Get authorize URL to initiate the flow
    const authorizeResponse = await identityFederationController.sso.getAuthorizeUrl({
      request: samlRequestFromSP,
      relayState: relayStateFromSP,
      samlBinding: 'HTTP-Redirect',
    });

    const jacksonRelayState = new URL(authorizeResponse.redirect_url).searchParams.get('RelayState');

    // Stub validate and spy on createSAMLResponse
    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: 'https://saml.boxyhq.com',
      claims: {
        id: '00u3e3cmpdDydXdzV5d7',
        email: 'kiran@boxyhq.com',
        firstName: 'Kiran',
        lastName: 'Krishnan',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': 'kiran@boxyhq.com',
      },
      issuer: 'https://saml.example.com/entityid',
      sessionIndex: '_a30730c45288bbc4986b',
    });

    const createSAMLResponseSpy = sinon.spy(saml, 'createSAMLResponse');

    // Process the SAML response
    const response = await oauthController.samlResponse({
      SAMLResponse: samlResponseFromIdP,
      RelayState: jacksonRelayState ?? '',
    });

    t.ok(response, 'Should return a response');
    t.ok('response_form' in response, 'Response should contain response_form');

    // Verify createSAMLResponse was called with ttlInMinutes
    t.ok(createSAMLResponseSpy.calledOnce, 'createSAMLResponse should be called once');

    const callArgs = createSAMLResponseSpy.firstCall.args[0] as any;
    t.equal(callArgs.ttlInMinutes, 30, 'createSAMLResponse should be called with ttlInMinutes: 30');

    stubValidate.restore();
    createSAMLResponseSpy.restore();
  });
});

tap.test('Federated SAML flow without ttlInMinutes should pass undefined', async (t) => {
  const noTtlTenant = 'boxyhq-no-ttl';
  const noTtlProduct = 'flex-no-ttl';
  // Use the same acsUrl as in request.xml to avoid ACS URL mismatch
  const noTtlServiceProvider = {
    acsUrl: 'https://twilio.com/saml2/acs',
    entityId: 'https://twilio.com/saml2/entityId/no-ttl',
  };

  let appWithoutTtl: IdentityFederationApp;

  t.before(async () => {
    // Create app without ttlInMinutes
    appWithoutTtl = await identityFederationController.app.create({
      name: 'Test App without TTL',
      tenant: noTtlTenant,
      product: noTtlProduct,
      entityId: noTtlServiceProvider.entityId,
      acsUrl: noTtlServiceProvider.acsUrl,
    });

    // Create SAML connection
    await connectionAPIController.createSAMLConnection({
      tenant: noTtlTenant,
      product: noTtlProduct,
      rawMetadata: await fs.readFile(path.join(__dirname, '/data/metadata.xml'), 'utf8'),
      defaultRedirectUrl: 'http://localhost:3366/sso/callback',
      redirectUrl: '["http://localhost:3366"]',
    });
  });

  t.teardown(async () => {
    await identityFederationController.app.delete({ id: appWithoutTtl.id });
    await connectionAPIController.deleteConnections({ tenant: noTtlTenant, product: noTtlProduct });
  });

  t.test('App should be created without ttlInMinutes', async (t) => {
    t.equal(appWithoutTtl.ttlInMinutes, null, 'App should not have ttlInMinutes set');
  });

  t.test('SAML Response should have undefined ttlInMinutes when not configured', async (t) => {
    const relayStateFromSP = 'sp-saml-request-relay-state-no-ttl';

    // Read SAML request/response - use original request.xml values (entityId must match app's entityId)
    const requestXML = (await fs.readFile(path.join(__dirname, '/data/request.xml'), 'utf8')).replace(
      'https://twilio.com/saml2/entityId',
      noTtlServiceProvider.entityId
    );
    const responseXML = await fs.readFile(path.join(__dirname, '/data/response.xml'), 'utf8');

    const samlRequestFromSP = Buffer.from(await deflateRawAsync(requestXML)).toString('base64');
    const samlResponseFromIdP = Buffer.from(responseXML).toString('base64');

    // Get authorize URL to initiate the flow
    const authorizeResponse = await identityFederationController.sso.getAuthorizeUrl({
      request: samlRequestFromSP,
      relayState: relayStateFromSP,
      samlBinding: 'HTTP-Redirect',
    });

    const jacksonRelayState = new URL(authorizeResponse.redirect_url).searchParams.get('RelayState');

    // Stub validate and spy on createSAMLResponse
    const stubValidate = sinon.stub(saml, 'validate').resolves({
      audience: 'https://saml.boxyhq.com',
      claims: {
        id: '00u3e3cmpdDydXdzV5d7',
        email: 'kiran@boxyhq.com',
        firstName: 'Kiran',
        lastName: 'Krishnan',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': 'kiran@boxyhq.com',
      },
      issuer: 'https://saml.example.com/entityid',
      sessionIndex: '_a30730c45288bbc4986b',
    });

    const createSAMLResponseSpy = sinon.spy(saml, 'createSAMLResponse');

    // Process the SAML response
    const response = await oauthController.samlResponse({
      SAMLResponse: samlResponseFromIdP,
      RelayState: jacksonRelayState ?? '',
    });

    t.ok(response, 'Should return a response');
    t.ok('response_form' in response, 'Response should contain response_form');

    // Verify createSAMLResponse was called without ttlInMinutes (undefined)
    t.ok(createSAMLResponseSpy.calledOnce, 'createSAMLResponse should be called once');

    const callArgs = createSAMLResponseSpy.firstCall.args[0] as any;
    t.equal(
      callArgs.ttlInMinutes,
      null,
      'createSAMLResponse should be called with ttlInMinutes: null when not configured'
    );

    stubValidate.restore();
    createSAMLResponseSpy.restore();
  });
});
