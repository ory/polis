import { JacksonError } from '../../controller/error';
import { SSOHandler } from '../../controller/sso-handler';
import { GENERIC_ERR_STRING, getErrorMessage, isConnectionActive } from '../../controller/utils';
import {
  IdentityFederationApp,
  JacksonOptionWithRequiredLogger,
  OIDCIdPInitiatedReq,
  OIDCSSORecord,
  SSOTrace,
  SSOTracesInstance,
} from '../../typings';
import * as metrics from '../../opentelemetry/metrics';
import { throwIfInvalidLicense } from '../common/checkLicense';
import { App } from './app';

export class IdPLogin {
  private ssoHandler: SSOHandler;
  private ssoTraces: SSOTracesInstance;
  private app: App;
  private opts: JacksonOptionWithRequiredLogger;

  constructor({ app, ssoHandler, ssoTraces, opts }) {
    this.app = app;
    this.ssoHandler = ssoHandler;
    this.ssoTraces = ssoTraces;
    this.opts = opts;
  }

  // Supported for SAML Federation only
  public async oidcInitiateLogin(
    body: OIDCIdPInitiatedReq & { fedAppId: string }
  ): Promise<{ redirect_url: string }> {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);
    const protocol = 'saml-federation';
    const login_type = 'idp-initiated';

    metrics.increment('idfedAuthorize', { protocol, login_type });

    let connection: OIDCSSORecord | undefined;
    let fedApp: IdentityFederationApp | undefined;
    const { iss, target_link_uri, fedAppId } = body;
    const context = {
      isSAMLFederated: true,
      relayState: target_link_uri,
      isIdPFlow: true,
      oidcIdPRequest: body,
    } as unknown as SSOTrace['context'];

    try {
      // get federated connection
      fedApp = await this.app.get({
        id: fedAppId,
      });

      const requestedTenant = fedApp.tenant;
      const requestedProduct = fedApp.product;

      context.tenant = requestedTenant;
      context.product = requestedProduct;

      if (fedApp.type !== 'saml') {
        throw new JacksonError(
          GENERIC_ERR_STRING,
          403,
          'Third party login from an OIDC provider is only supported with SAML Federation'
        );
      }

      const response = await this.ssoHandler.resolveConnection({
        tenant: requestedTenant,
        product: requestedProduct,
        authFlow: 'idp-initiated',
        originalParams: { ...body },
        tenants: fedApp.tenants,
        idFedAppId: fedApp.id,
        fedType: fedApp.type, // will be saml
        thirdPartyLogin: { idpInitiatorType: 'oidc', iss, target_link_uri },
        ssoTraces: { instance: this.ssoTraces, context },
      });

      if ('connection' in response) {
        connection = response.connection as OIDCSSORecord;
      }

      if (!connection) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'IdP connection not found.');
      }

      context.clientID = connection.clientID;
      context.providerName = connection?.oidcProvider.provider || '';
      context.acsUrl = fedApp.acsUrl;
      context.entityId = fedApp.entityId;

      if (!isConnectionActive(connection)) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'OIDC connection is deactivated.');
      }

      const requestParams = {
        acsUrl: fedApp.acsUrl,
        entityId: fedApp.entityId,
        tenant: fedApp.tenant,
        product: fedApp.product,
        relayState: target_link_uri,
        oidcIdPRequest: body,
        fedAppSamlAudienceOverride: fedApp.samlAudienceOverride,
      };

      return await this.ssoHandler.createOIDCRequest({
        connection,
        requestParams,
        mappings: fedApp.mappings,
        includeOidcTokensInAssertion: fedApp.includeOidcTokensInAssertion,
        ssoTraces: {
          instance: this.ssoTraces,
          context,
        },
      });
    } catch (err: unknown) {
      const error_description = getErrorMessage(err);
      metrics.increment('idfedAuthorizeError', { protocol, login_type });
      this.ssoTraces.saveTrace({
        error: error_description,
        context,
      });

      throw err;
    }
  }
}
