import saml from '@boxyhq/saml20';

import { App } from './app';
import { JacksonError } from '../../controller/error';
import { SSOHandler } from '../../controller/sso-handler';
import type {
  OIDCSSORecord,
  IdentityFederationApp,
  SAMLSSORecord,
  SSOTracesInstance,
  SSOTrace,
  JacksonOptionWithRequiredLogger,
} from '../../typings';
import * as metrics from '../../opentelemetry/metrics';
import { GENERIC_ERR_STRING, getErrorMessage, isConnectionActive } from '../../controller/utils';
import { throwIfInvalidLicense } from '../common/checkLicense';

const isSAMLConnection = (connection: SAMLSSORecord | OIDCSSORecord): connection is SAMLSSORecord => {
  return 'idpMetadata' in connection;
};

export class SSO {
  private app: App;
  private ssoHandler: SSOHandler;
  private ssoTraces: SSOTracesInstance;
  private opts: JacksonOptionWithRequiredLogger;

  constructor({
    app,
    ssoHandler,
    ssoTraces,
    opts,
  }: {
    app: App;
    ssoHandler: SSOHandler;
    ssoTraces: SSOTracesInstance;
    opts: JacksonOptionWithRequiredLogger;
  }) {
    this.app = app;
    this.ssoHandler = ssoHandler;
    this.ssoTraces = ssoTraces;
    this.opts = opts;
  }

  // Accept the SAML Request from Service Provider, and create a new SAML Request to be sent to Identity Provider
  public getAuthorizeUrl = async ({
    request,
    relayState,
    idp_hint,
    samlBinding,
  }: {
    request: string;
    relayState: string;
    samlBinding: 'HTTP-POST' | 'HTTP-Redirect';
    idp_hint?: string;
  }) => {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    const protocol = 'saml-federation';
    const login_type = 'sp-initiated';

    metrics.increment('idfedAuthorize', { protocol, login_type });

    const isPostBinding = samlBinding === 'HTTP-POST';
    let connection: SAMLSSORecord | OIDCSSORecord | undefined;
    let app: IdentityFederationApp | undefined;
    let id, acsUrl, entityId, publicKey, providerName, decodedRequest;
    const context = { isSAMLFederated: true, relayState } as unknown as SSOTrace['context'];

    try {
      decodedRequest = await saml.decodeBase64(request, !isPostBinding);
      context.samlRequest = decodedRequest || request;

      const parsedSAMLRequest = await saml.parseSAMLRequest(decodedRequest, isPostBinding);

      id = parsedSAMLRequest.id;
      entityId = parsedSAMLRequest.audience;
      publicKey = parsedSAMLRequest.publicKey;
      providerName = parsedSAMLRequest.providerName;
      context.entityId = entityId;
      context.providerName = providerName;

      // Verify the request if it is signed
      if (publicKey && !saml.validateSignature(decodedRequest, publicKey, null)) {
        throw new JacksonError(GENERIC_ERR_STRING, 400, 'Invalid SAML Request signature.');
      }

      app = await this.app.getByEntityId(entityId);
      acsUrl = parsedSAMLRequest.acsUrl || app.acsUrl; // acsUrl is optional in the SAMLRequest
      context.tenant = app.tenant;
      context.product = app.product;
      context.acsUrl = acsUrl;

      if (app.acsUrl !== acsUrl) {
        throw new JacksonError(GENERIC_ERR_STRING, 400, "Assertion Consumer Service URL doesn't match.");
      }

      const response = await this.ssoHandler.resolveConnection({
        tenant: app.tenant,
        product: app.product,
        idp_hint,
        authFlow: 'saml',
        idFedAppId: app.id,
        originalParams: { RelayState: relayState, SAMLRequest: request, samlBinding },
        tenants: app.tenants,
      });

      // If there is a redirect URL, then we need to redirect to that URL
      if ('redirectUrl' in response) {
        return { redirect_url: response.redirectUrl, authorize_form: null };
      }

      // If there is a connection, use that connection
      if ('connection' in response) {
        connection = response.connection;
      }

      if (!connection) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'No SSO connection found.');
      }

      context.clientID = connection.clientID;

      if (!isConnectionActive(connection)) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'SSO connection is deactivated.');
      }

      const requestParams = {
        id,
        acsUrl,
        entityId,
        publicKey,
        providerName,
        relayState,
        tenant: app.tenant,
        product: app.product,
        fedAppSamlAudienceOverride: app.samlAudienceOverride,
        ttlInMinutes: app.ttlInMinutes,
      };

      return isSAMLConnection(connection)
        ? await this.ssoHandler.createSAMLRequest({ connection, requestParams, mappings: app.mappings })
        : await this.ssoHandler.createOIDCRequest({
            connection,
            requestParams,
            mappings: app.mappings,
            ssoTraces: { instance: this.ssoTraces, context },
          });
    } catch (err: unknown) {
      const error_description = getErrorMessage(err);
      metrics.increment('idfedAuthorizeError', { protocol, login_type });

      this.ssoTraces.saveTrace({ error: error_description, context });

      throw err;
    }
  };
}
