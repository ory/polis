import tap from 'tap';
import path from 'path';
import { promisify } from 'util';
import { deflateRaw } from 'zlib';
import { promises as fs } from 'fs';

import { jacksonOptions } from '../utils';
import { tenant as victimTenant, product as victimProduct, serviceProvider } from './constants';
import type {
  IIdentityFederationController,
  IConnectionAPIController,
  IdentityFederationApp,
  SAMLSSORecord,
} from '../../src';

const deflateRawAsync = promisify(deflateRaw);

// Victim IdP SSO URL from data/metadata.xml.
const VICTIM_IDP_SSO = 'https://mocksaml.com/api/saml/sso';
// Attacker-controlled IdP SSO URL used only in the attacker's own metadata.
const ATTACKER_IDP_SSO = 'https://attacker-evil.example.com/sso';

const attackerTenant = 'attacker-tenant';
const attackerProduct = 'attacker-product';

let identityFederationController: IIdentityFederationController;
let connectionAPIController: IConnectionAPIController;

let app: IdentityFederationApp;
let victimConnection: SAMLSSORecord;
let attackerConnection: SAMLSSORecord;
let forgedRequest: string;

tap.before(async () => {
  const jackson = await (await import('../../src/index')).default(jacksonOptions);

  identityFederationController = jackson.identityFederationController;
  connectionAPIController = jackson.connectionAPIController;

  const victimMetadata = await fs.readFile(path.join(__dirname, '/data/metadata.xml'), 'utf8');

  // The attacker registers their own IdP connection in their own tenant. Its
  // EntityID must differ from the victim's, because connection creation rejects
  // reusing an EntityID across tenants.
  const attackerMetadata = victimMetadata
    .split('https://saml.example.com/entityid')
    .join('https://saml.attacker.com/entityid')
    .split(VICTIM_IDP_SSO)
    .join(ATTACKER_IDP_SSO);

  // Victim federation app and its own legitimate IdP connection.
  app = await identityFederationController.app.create({
    name: 'Victim App',
    tenant: victimTenant,
    product: victimProduct,
    entityId: serviceProvider.entityId,
    acsUrl: serviceProvider.acsUrl,
  });

  victimConnection = await connectionAPIController.createSAMLConnection({
    tenant: victimTenant,
    product: victimProduct,
    rawMetadata: victimMetadata,
    defaultRedirectUrl: 'http://localhost:3366/sso/callback',
    redirectUrl: '["http://localhost:3366"]',
  });

  // Attacker IdP connection, in the attacker's own tenant/product.
  attackerConnection = await connectionAPIController.createSAMLConnection({
    tenant: attackerTenant,
    product: attackerProduct,
    rawMetadata: attackerMetadata,
    defaultRedirectUrl: 'http://localhost:3366/sso/callback',
    redirectUrl: '["http://localhost:3366"]',
  });

  // Forged (unsigned) SP AuthnRequest for the victim app: its issuer/ACS match
  // the victim service provider.
  const requestXML = await fs.readFile(path.join(__dirname, '/data/request.xml'), 'utf8');
  forgedRequest = Buffer.from(await deflateRawAsync(requestXML)).toString('base64');
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('idp_hint must be scoped to the requesting federation app', async (t) => {
  t.teardown(async () => {
    await identityFederationController.app.delete({ id: app.id });
    await connectionAPIController.deleteConnections({ tenant: victimTenant, product: victimProduct });
    await connectionAPIController.deleteConnections({ tenant: attackerTenant, product: attackerProduct });
  });

  t.test('no idp_hint routes to the victim IdP (baseline)', async (t) => {
    const response = await identityFederationController.sso.getAuthorizeUrl({
      request: forgedRequest,
      relayState: 'baseline',
      samlBinding: 'HTTP-Redirect',
    });

    t.ok(
      response.redirect_url?.startsWith(VICTIM_IDP_SSO),
      'Without idp_hint the login goes to the victim IdP'
    );
  });

  t.test('idp_hint for the victim app own connection is allowed', async (t) => {
    const response = await identityFederationController.sso.getAuthorizeUrl({
      request: forgedRequest,
      relayState: 'in-scope',
      samlBinding: 'HTTP-Redirect',
      idp_hint: victimConnection.clientID,
    });

    t.ok(
      response.redirect_url?.startsWith(VICTIM_IDP_SSO),
      'In-scope idp_hint still resolves to the victim IdP'
    );
  });

  t.test('idp_hint for a cross-tenant connection is rejected', async (t) => {
    try {
      await identityFederationController.sso.getAuthorizeUrl({
        request: forgedRequest,
        relayState: 'attack',
        samlBinding: 'HTTP-Redirect',
        idp_hint: attackerConnection.clientID, // attacker's own cross-tenant connection
      });
      t.fail('Cross-tenant idp_hint should be rejected, not routed to the attacker IdP');
    } catch (err: any) {
      t.equal(err.statusCode, 403, 'Cross-tenant idp_hint is rejected with a 403');
    }
  });
});
