import crypto from 'crypto';
import { promisify } from 'util';
import { deflateRaw } from 'zlib';
import saml from '@boxyhq/saml20';
import { validateSSOURL } from './utils';
import { SAMLProfile } from '@boxyhq/saml20/dist/typings';
import type {
  IOAuthController,
  OAuthReq,
  OAuthTokenReq,
  OAuthTokenRes,
  Profile,
  SAMLResponsePayload,
  Storable,
  SAMLSSORecord,
  OIDCSSORecord,
  SSOTrace,
  SSOTracesInstance as ssoTraces,
  OAuthErrorHandlerParams,
  OIDCAuthzResponsePayload,
  IdentityFederationApp,
  JacksonOptionWithRequiredLogger,
} from '../typings';
import {
  AuthorizationCodeGrantResult,
  clientIDFederatedPrefix,
  clientIDOIDCPrefix,
  relayStatePrefix,
  IndexNames,
  OAuthErrorResponse,
  getErrorMessage,
  loadJWSPrivateKey,
  computeKid,
  isJWSKeyPairLoaded,
  extractOIDCUserProfile,
  getScopeValues,
  getEncodedTenantProduct,
  isConnectionActive,
  dynamicImport,
  GENERIC_ERR_STRING,
} from './utils';

import * as metrics from '../opentelemetry/metrics';
import { JacksonError } from './error';
import * as allowed from './oauth/allowed';
import * as codeVerifier from './oauth/code-verifier';
import * as redirect from './oauth/redirect';
import { getDefaultCertificate } from '../saml/x509';
import { SSOHandler } from './sso-handler';
import { ValidateOption, extractSAMLResponseAttributes } from '../saml/lib';
import { oidcClientConfig } from './oauth/oidc-client';
import { App } from '../ee/identity-federation/app';
import * as encrypter from '../db/encrypter';
import { Encrypted } from '../typings';

const deflateRawAsync = promisify(deflateRaw);

function encrypt(val: any) {
  const genKey = crypto.randomBytes(32);
  const hexKey = genKey.toString('hex');
  const encVal = encrypter.encrypt(JSON.stringify(val), genKey);
  return { hexKey, encVal };
}

function decrypt(res: Encrypted, encryptionKey: string) {
  const encKey = Buffer.from(encryptionKey, 'hex');
  if (res.iv && res.tag) {
    return JSON.parse(encrypter.decrypt(res.value, res.iv, res.tag, encKey));
  }

  return JSON.parse(res.value);
}

export class OAuthController implements IOAuthController {
  private connectionStore: Storable;
  private sessionStore: Storable;
  private codeStore: Storable;
  private tokenStore: Storable;
  private ssoTraces: ssoTraces;
  private opts: JacksonOptionWithRequiredLogger;
  private ssoHandler: SSOHandler;
  private idFedApp: App;

  constructor({ connectionStore, sessionStore, codeStore, tokenStore, ssoTraces, opts, idFedApp }) {
    this.connectionStore = connectionStore;
    this.sessionStore = sessionStore;
    this.codeStore = codeStore;
    this.tokenStore = tokenStore;
    this.ssoTraces = ssoTraces;
    this.opts = opts;
    this.idFedApp = idFedApp;

    this.ssoHandler = new SSOHandler({ connection: connectionStore, session: sessionStore, opts });
  }

  public async authorize(
    body: OAuthReq
  ): Promise<{ redirect_url?: string; authorize_form?: string; error?: string }> {
    const {
      tenant,
      product,
      access_type,
      resource,
      response_type = 'code',
      client_id,
      redirect_uri,
      state,
      scope,
      nonce,
      code_challenge,
      code_challenge_method = '',
      idp_hint,
      forceAuthn = 'false',
      login_hint,
      ...oidcParams // Rest of the params will be assumed as OIDC params and will be forwarded to the IdP
    } = body;

    let requestedTenant;
    let requestedProduct;
    let requestedScopes: string[] | undefined;
    let requestedOIDCFlow: boolean | undefined;
    let isOIDCFederated: boolean | undefined;
    let connection: SAMLSSORecord | OIDCSSORecord | undefined;
    let fedApp: IdentityFederationApp | undefined;
    let connectionIsSAML;
    let connectionIsOIDC;
    let protocol;
    const login_type = 'sp-initiated';

    try {
      requestedTenant = tenant;
      requestedProduct = product;

      metrics.increment('oauthAuthorize');

      if (!redirect_uri) {
        throw new JacksonError('Please specify a redirect URL.', 400);
      }

      requestedScopes = getScopeValues(scope);
      requestedOIDCFlow = requestedScopes.includes('openid');

      if (tenant && product) {
        const response = await this.ssoHandler.resolveConnection({
          tenant,
          product,
          idp_hint,
          authFlow: 'oauth',
          originalParams: { ...body },
        });

        if ('redirectUrl' in response) {
          return { redirect_url: response.redirectUrl };
        }

        if ('connection' in response) {
          connection = response.connection;
        }
      } else if (client_id && client_id !== '' && client_id !== 'undefined' && client_id !== 'null') {
        // if tenant and product are encoded in the client_id then we parse it and check for the relevant connection(s)
        let sp = getEncodedTenantProduct(client_id);

        if (!sp && access_type) {
          sp = getEncodedTenantProduct(access_type);
        }
        if (!sp && resource) {
          sp = getEncodedTenantProduct(resource);
          if (sp === null) {
            oidcParams.resource = resource;
          }
        }
        if (!sp && requestedScopes) {
          const encodedParams = requestedScopes.find((scope) => scope.includes('=') && scope.includes('&')); // for now assume only one encoded param i.e. for tenant/product
          if (encodedParams) {
            sp = getEncodedTenantProduct(encodedParams);
          }
        }
        if (sp && sp.tenant && sp.product) {
          const { tenant, product } = sp;

          requestedTenant = tenant;
          requestedProduct = product;

          const response = await this.ssoHandler.resolveConnection({
            tenant,
            product,
            idp_hint,
            authFlow: 'oauth',
            originalParams: { ...body },
          });

          if ('redirectUrl' in response) {
            return { redirect_url: response.redirectUrl };
          }

          if ('connection' in response) {
            connection = response.connection;
          }
        } else {
          // client_id is not encoded, so we look for the connection using the client_id
          // First we check if it's a federated connection
          if (client_id.startsWith(`${clientIDFederatedPrefix}${clientIDOIDCPrefix}`)) {
            isOIDCFederated = true;
            protocol = 'oidc-federation';
            metrics.increment('idfedAuthorize', { protocol, login_type });
            fedApp = await this.idFedApp.get({ id: client_id.replace(clientIDFederatedPrefix, '') });

            const response = await this.ssoHandler.resolveConnection({
              tenant: fedApp.tenant,
              product: fedApp.product,
              idp_hint,
              authFlow: 'oauth',
              originalParams: { ...body },
              tenants: fedApp.tenants,
              idFedAppId: fedApp.id,
              fedType: fedApp.type,
            });

            if ('redirectUrl' in response) {
              return { redirect_url: response.redirectUrl };
            }

            if ('connection' in response) {
              connection = response.connection;
              requestedTenant = fedApp.tenant;
              requestedProduct = fedApp.product;
            }
          } else {
            // If it's not a federated connection, we look for the connection using the client_id
            connection = await this.connectionStore.get(client_id);
            if (connection) {
              requestedTenant = connection.tenant;
              requestedProduct = connection.product;
            }
          }
        }
      } else {
        throw new JacksonError('You need to specify client_id or tenant & product', 403);
      }

      if (!connection) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'IdP connection not found.');
      }

      connectionIsSAML = 'idpMetadata' in connection && connection.idpMetadata !== undefined;
      connectionIsOIDC = 'oidcProvider' in connection && connection.oidcProvider !== undefined;
      protocol = isOIDCFederated ? 'oidc-federation' : connectionIsSAML ? 'saml' : 'oidc';

      if (
        !allowed.redirect(
          redirect_uri,
          connection.redirectUrl as string[],
          this.opts.openid?.redirectExactMatch
        )
      ) {
        if (fedApp) {
          if (
            !allowed.redirect(
              redirect_uri,
              fedApp.redirectUrl as string[],
              this.opts.openid?.redirectExactMatch
            )
          ) {
            throw new JacksonError('Redirect URL is not allowed.', 403);
          }
        } else {
          throw new JacksonError('Redirect URL is not allowed.', 403);
        }
      }

      if (!isConnectionActive(connection)) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'SSO connection is deactivated.');
      }
    } catch (err: unknown) {
      const error_description = getErrorMessage(err);
      metrics.increment(isOIDCFederated ? 'idfedAuthorizeError' : 'oauthAuthorizeError', {
        protocol,
        login_type,
      });
      // Save the error trace
      await this.ssoTraces.saveTrace({
        error: error_description,
        context: {
          tenant: requestedTenant || '',
          product: requestedProduct || '',
          clientID: connection?.clientID || '',
          requestedOIDCFlow,
          isOIDCFederated,
          redirectUri: redirect_uri,
        },
      });
      throw err;
    }

    const isMissingJWTKeysForOIDCFlow =
      requestedOIDCFlow &&
      (!this.opts.openid?.jwtSigningKeys || !isJWSKeyPairLoaded(this.opts.openid.jwtSigningKeys));

    const oAuthClientReqError = !state || response_type !== 'code';

    if (isMissingJWTKeysForOIDCFlow || oAuthClientReqError || (!connectionIsSAML && !connectionIsOIDC)) {
      let error, error_description, internalError;
      if (isMissingJWTKeysForOIDCFlow) {
        error = 'server_error';
        internalError =
          'Authorize error: OAuth server not configured correctly for openid flow, check if JWT signing keys are loaded';
        error_description = GENERIC_ERR_STRING;
        this.opts.logger.error(internalError);
      }

      if (!state) {
        error = 'invalid_request';
        error_description = 'Please specify a state to safeguard against XSRF attacks';
      }

      if (response_type !== 'code') {
        error = 'unsupported_response_type';
        error_description = 'Only Authorization Code grant is supported';
      }

      if (!connectionIsSAML && !connectionIsOIDC) {
        error = 'server_error';
        internalError = 'Authorize error: Connection appears to be misconfigured';
        error_description = GENERIC_ERR_STRING;
        this.opts.logger.error(internalError);
      }

      metrics.increment('oauthAuthorizeError', { protocol, login_type });

      // Save the error trace
      const traceId = await this.ssoTraces.saveTrace({
        error: internalError ?? error_description,
        context: {
          tenant: requestedTenant,
          product: requestedProduct,
          clientID: connection.clientID,
          requestedOIDCFlow,
          isOIDCFederated,
          redirectUri: redirect_uri,
        },
      });
      return {
        redirect_url: OAuthErrorResponse({
          error,
          error_description: traceId ? `${traceId}: ${error_description}` : error_description,
          redirect_uri,
          state,
        }),
        error: `${error} - ${error_description}`,
      };
    }

    // Connection retrieved: Handover to IdP starts here
    let ssoUrl;
    let post = false;
    let providerName;

    // Init sessionId
    const sessionId = crypto.randomBytes(16).toString('hex');
    const relayState = relayStatePrefix + sessionId;
    // SAML connection: SAML request will be constructed here
    let samlReq, internalError;
    if (connectionIsSAML) {
      try {
        const { sso, provider } = (connection as SAMLSSORecord).idpMetadata;
        providerName = provider;

        if ('redirectUrl' in sso) {
          // HTTP Redirect binding
          ssoUrl = sso.redirectUrl;
        } else if ('postUrl' in sso) {
          // HTTP-POST binding
          ssoUrl = sso.postUrl;
          post = true;
        } else {
          // This code here is kept for backward compatibility. We now have validation while adding the SSO connection to ensure binding is present.
          internalError = 'Authorize error: SAML binding could not be retrieved';
          const error_description = GENERIC_ERR_STRING;
          this.opts.logger.error(internalError);

          metrics.increment('oauthAuthorizeError', { protocol, login_type });
          // Save the error trace
          const traceId = await this.ssoTraces.saveTrace({
            error: internalError ?? error_description,
            context: {
              tenant: requestedTenant as string,
              product: requestedProduct as string,
              clientID: connection.clientID,
              requestedOIDCFlow,
              isOIDCFederated,
              redirectUri: redirect_uri,
              providerName: provider,
            },
          });
          return {
            redirect_url: OAuthErrorResponse({
              error: 'invalid_request',
              error_description: traceId ? `${traceId}: ${error_description}` : error_description,
              redirect_uri,
              state,
            }),
          };
        }

        validateSSOURL(ssoUrl);

        const cert = await getDefaultCertificate();

        samlReq = saml.request({
          ssoUrl,
          entityID: connection.samlAudienceOverride
            ? connection.samlAudienceOverride
            : this.opts.samlAudience!,
          callbackUrl: connection.acsUrlOverride ? connection.acsUrlOverride : (this.opts.acsUrl as string),
          signingKey: cert.privateKey,
          publicKey: cert.publicKey,
          forceAuthn: forceAuthn === 'true' ? true : !!(connection as SAMLSSORecord).forceAuthn,
          identifierFormat: (connection as SAMLSSORecord).identifierFormat
            ? (connection as SAMLSSORecord).identifierFormat
            : 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        });
      } catch (err: unknown) {
        const error_description = getErrorMessage(err);
        this.opts.logger.error(`Authorize error: ${error_description} `);
        metrics.increment('oauthAuthorizeError', { protocol, login_type });
        // Save the error trace
        const traceId = await this.ssoTraces.saveTrace({
          error: error_description,
          context: {
            tenant: requestedTenant,
            product: requestedProduct,
            clientID: connection.clientID,
            requestedOIDCFlow,
            isOIDCFederated,
            redirectUri: redirect_uri,
          },
        });

        return {
          redirect_url: OAuthErrorResponse({
            error: 'server_error',
            error_description: traceId ? `${traceId}: ${error_description}` : error_description,
            redirect_uri,
            state,
          }),
        };
      }
    }

    // OIDC Connection: Issuer discovery, openid-client init and extraction of authorization endpoint happens here
    let oidcCodeVerifier: string | undefined;
    let oidcNonce: string | undefined;
    if (connectionIsOIDC) {
      const { discoveryUrl, metadata, clientId, clientSecret, provider } = (connection as OIDCSSORecord)
        .oidcProvider;
      providerName = provider;
      const { ssoTraces } = this;
      try {
        if (!this.opts.oidcPath) {
          throw new JacksonError(
            GENERIC_ERR_STRING,
            500,
            'OpenID response handler path (oidcPath) is not set'
          );
        }
        const client = (await dynamicImport('openid-client')) as typeof import('openid-client');
        const oidcConfig = await oidcClientConfig({
          discoveryUrl,
          metadata,
          clientId,
          clientSecret,
          ssoTraces: {
            instance: ssoTraces,
            context: {
              tenant: requestedTenant as string,
              product: requestedProduct as string,
              clientID: connection.clientID,
              requestedOIDCFlow,
              isOIDCFederated,
              redirectUri: redirect_uri,
              providerName: provider,
            },
          },
        });
        oidcCodeVerifier = client.randomPKCECodeVerifier();
        const code_challenge = await client.calculatePKCECodeChallenge(oidcCodeVerifier);
        oidcNonce = client.randomNonce();
        const standardScopes = this.opts.openid?.requestProfileScope
          ? ['openid', 'email', 'profile']
          : ['openid', 'email'];
        const paramsToForward = this.opts.openid?.forwardOIDCParams ? oidcParams : {};
        if (login_hint) {
          paramsToForward.login_hint = login_hint;
        }
        ssoUrl = client.buildAuthorizationUrl(oidcConfig, {
          scope: [...requestedScopes, ...standardScopes]
            .filter((value, index, self) => self.indexOf(value) === index) // filter out duplicates
            .join(' '),
          code_challenge,
          code_challenge_method: 'S256',
          state: relayState,
          nonce: oidcNonce,
          redirect_uri: this.opts.externalUrl + this.opts.oidcPath,
          ...paramsToForward,
        }).href;
      } catch (err: unknown) {
        const error_description = getErrorMessage(err);
        this.opts.logger.error(`Authorize error: ${error_description}`);
        metrics.increment('oauthAuthorizeError', { protocol, login_type });
        // Save the error trace
        const traceId = await this.ssoTraces.saveTrace({
          error: error_description,
          context: {
            tenant: requestedTenant as string,
            product: requestedProduct as string,
            clientID: connection.clientID,
            requestedOIDCFlow,
            isOIDCFederated,
            redirectUri: redirect_uri,
            providerName,
          },
        });

        if (err) {
          return {
            redirect_url: OAuthErrorResponse({
              error: 'server_error',
              error_description: traceId ? `${traceId}: ${error_description}` : error_description,
              redirect_uri,
              state,
            }),
          };
        }
      }
    }
    // Session persistence happens here
    try {
      const requested = {
        client_id,
        state,
        redirect_uri,
        protocol,
        login_type,
        providerName,
        login_hint,
      } as Record<string, string | boolean | string[]>;
      if (requestedTenant) {
        requested.tenant = requestedTenant;
      }
      if (requestedProduct) {
        requested.product = requestedProduct;
      }
      if (idp_hint) {
        requested.idp_hint = idp_hint;
      } else {
        if (fedApp) {
          requested.idp_hint = connection.clientID;
        }
      }
      if (requestedOIDCFlow) {
        requested.oidc = true;
        if (nonce) {
          requested.nonce = nonce;
        }
      }
      if (requestedScopes) {
        requested.scope = requestedScopes;
      }

      const sessionObj = {
        redirect_uri,
        response_type,
        state,
        code_challenge,
        code_challenge_method,
        requested,
        oidcFederated: fedApp
          ? {
              redirectUrl: fedApp.redirectUrl,
              id: fedApp.id,
              clientID: fedApp.clientID,
              clientSecret: fedApp.clientSecret,
              ttlInMinutes: fedApp.ttlInMinutes,
            }
          : undefined,
      };
      await this.sessionStore.put(
        sessionId,
        connectionIsSAML
          ? { ...sessionObj, id: samlReq?.id }
          : { ...sessionObj, id: connection.clientID, oidcCodeVerifier, oidcNonce }
      );
      // Redirect to IdP
      if (connectionIsSAML) {
        let redirectUrl;
        let authorizeForm;

        if (!post) {
          // HTTP Redirect binding
          redirectUrl = redirect.success(ssoUrl, {
            RelayState: relayState,
            SAMLRequest: Buffer.from(await deflateRawAsync(samlReq.request)).toString('base64'),
          });
        } else {
          // HTTP POST binding
          authorizeForm = saml.createPostForm(ssoUrl, [
            { name: 'RelayState', value: relayState },
            { name: 'SAMLRequest', value: Buffer.from(samlReq.request).toString('base64') },
          ]);
        }
        return { redirect_url: redirectUrl, authorize_form: authorizeForm };
      }
      if (connectionIsOIDC) {
        return { redirect_url: ssoUrl };
      }
      throw 'Connection appears to be misconfigured';
    } catch (err: unknown) {
      const error_description = getErrorMessage(err);
      metrics.increment('oauthAuthorizeError', { protocol, login_type });
      // Save the error trace
      const traceId = await this.ssoTraces.saveTrace({
        error: error_description,
        context: {
          tenant: requestedTenant as string,
          product: requestedProduct as string,
          clientID: connection.clientID,
          requestedOIDCFlow,
          isOIDCFederated,
          redirectUri: redirect_uri,
          samlRequest: samlReq?.request || '',
          providerName,
        },
      });
      return {
        redirect_url: OAuthErrorResponse({
          error: 'server_error',
          error_description: traceId ? `${traceId}: ${error_description}` : error_description,
          redirect_uri,
          state,
        }),
      };
    }
  }

  public async samlResponse(
    body: SAMLResponsePayload
  ): Promise<{ redirect_url?: string; app_select_form?: string; response_form?: string; error?: string }> {
    let connection: SAMLSSORecord | undefined;
    let rawResponse: string | undefined;
    let sessionId: string | undefined;
    let session: any;
    let issuer: string | undefined;
    let isIdPFlow: boolean | undefined;
    let isSAMLFederated: boolean | undefined;
    let isOIDCFederated: boolean | undefined;
    let validateOpts: ValidateOption;
    let redirect_uri: string | undefined;
    const { SAMLResponse, idp_hint, RelayState = '' } = body;
    let protocol, login_type;

    try {
      isIdPFlow = !RelayState.startsWith(relayStatePrefix);
      login_type = isIdPFlow ? 'idp-initiated' : 'sp-initiated';
      metrics.increment('oauthResponse', { protocol: 'saml', login_type });
      rawResponse = Buffer.from(SAMLResponse, 'base64').toString();
      issuer = saml.parseIssuer(rawResponse);

      if (!this.opts.idpEnabled && isIdPFlow) {
        // IdP login is disabled so block the request
        throw new JacksonError(
          GENERIC_ERR_STRING,
          403,
          'IdP (Identity Provider) flow has been disabled. Please head to your Service Provider to login.'
        );
      }

      if (isIdPFlow) {
        protocol = 'saml';
      }
      sessionId = RelayState.replace(relayStatePrefix, '');

      if (!issuer) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'Issuer not found.');
      }

      const connections: SAMLSSORecord[] = (
        await this.connectionStore.getByIndex({ name: IndexNames.EntityID, value: issuer })
      ).data;

      if (!connections || connections.length === 0) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'SAML connection not found.');
      }

      session = sessionId ? await this.sessionStore.get(sessionId) : null;

      if (!isIdPFlow && !session) {
        throw new JacksonError('Unable to validate state from the origin request.', 403);
      }

      isSAMLFederated = session && 'samlFederated' in session;
      isOIDCFederated = session && 'oidcFederated' in session;
      const isSPFlow = !isIdPFlow && !isSAMLFederated;
      protocol = isOIDCFederated ? 'oidc-federation' : isSAMLFederated ? 'saml-federation' : 'saml';
      if (protocol !== 'saml') {
        metrics.increment('idfedResponse', { protocol, login_type });
      }
      // IdP initiated SSO flow
      if (isIdPFlow) {
        const response = await this.ssoHandler.resolveConnection({
          idp_hint,
          authFlow: 'idp-initiated',
          entityId: issuer,
          originalParams: { SAMLResponse },
        });

        // Redirect to the product selection page
        if ('postForm' in response) {
          return { app_select_form: response.postForm };
        }

        // Found a connection
        if ('connection' in response) {
          connection = response.connection as SAMLSSORecord;
          if (!isConnectionActive(connection)) {
            throw new JacksonError(
              GENERIC_ERR_STRING,
              403,
              'SSO connection is deactivated. Please contact your administrator.'
            );
          }
        }
      }

      // SP initiated SSO flow
      // Resolve if there are multiple matches for SP login
      if (isSPFlow || isSAMLFederated || isOIDCFederated) {
        connection = connections.filter((c) => {
          return (
            c.clientID === session.requested.client_id ||
            c.clientID === session.requested.idp_hint ||
            (c.tenant === session.requested.tenant && c.product === session.requested.product)
          );
        })[0];
      }

      if (!connection) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'SAML connection not found.');
      }

      if (
        session &&
        session.redirect_uri &&
        !allowed.redirect(
          session.redirect_uri,
          connection.redirectUrl as string[],
          this.opts.openid?.redirectExactMatch
        )
      ) {
        if (isOIDCFederated) {
          if (
            !allowed.redirect(
              session.redirect_uri,
              session.oidcFederated?.redirectUrl as string[],
              this.opts.openid?.redirectExactMatch
            )
          ) {
            throw new JacksonError('Redirect URL is not allowed.', 403);
          }
        } else {
          throw new JacksonError('Redirect URL is not allowed.', 403);
        }
      }

      const { privateKey } = await getDefaultCertificate();

      validateOpts = {
        audience: connection.samlAudienceOverride ? connection.samlAudienceOverride : this.opts.samlAudience!,
        privateKey,
      };

      if (connection.idpMetadata.publicKey) {
        validateOpts.publicKey = connection.idpMetadata.publicKey;
      } else if (connection.idpMetadata.thumbprint) {
        validateOpts.thumbprint = connection.idpMetadata.thumbprint;
      }

      if (session && session.id) {
        validateOpts['inResponseTo'] = session.id;
      }

      redirect_uri = ((session && session.redirect_uri) as string) || connection.defaultRedirectUrl;
    } catch (err: unknown) {
      metrics.increment(isOIDCFederated || isSAMLFederated ? 'idfedResponseError' : 'oauthResponseError', {
        protocol,
        login_type,
      });
      // Save the error trace
      await this.ssoTraces.saveTrace({
        error: getErrorMessage(err),
        context: {
          samlResponse: rawResponse,
          tenant: session?.requested?.tenant || connection?.tenant,
          product: session?.requested?.product || connection?.product,
          clientID: session?.requested?.client_id || connection?.clientID,
          providerName: connection?.idpMetadata?.provider,
          redirectUri: isIdPFlow ? connection?.defaultRedirectUrl : session?.redirect_uri,
          issuer,
          isSAMLFederated,
          isOIDCFederated,
          isIdPFlow,
          requestedOIDCFlow: !!session?.requested?.oidc,
          acsUrl: session?.requested?.acsUrl,
          entityId: session?.requested?.entityId,
          relayState: RelayState,
        },
      });
      throw err; // Rethrow the error
    }
    let profile: SAMLProfile | undefined;

    try {
      profile = await extractSAMLResponseAttributes(rawResponse, validateOpts);

      // This is a federated SAML flow, let's create a new SAMLResponse and POST it to the SP
      if (isSAMLFederated) {
        const { responseForm } = await this.ssoHandler.createSAMLResponse({ profile, session });

        await this.sessionStore.delete(sessionId);

        return { response_form: responseForm };
      }

      const code = await this._buildAuthorizationCode(connection, profile, session, isIdPFlow);

      const params = { code };

      if (session && session.state) {
        params['state'] = session.state;
      }

      await this.sessionStore.delete(sessionId);

      return { redirect_url: redirect.success(redirect_uri, params) };
    } catch (err: unknown) {
      metrics.increment(isOIDCFederated || isSAMLFederated ? 'idfedResponseError' : 'oauthResponseError', {
        protocol,
        login_type,
      });
      const error_description = getErrorMessage(err);
      this.opts.logger.error(`SAMLResponse error: ${error_description}`);
      // Trace the error
      const traceId = await this.ssoTraces.saveTrace({
        error: error_description,
        context: {
          samlResponse: rawResponse,
          tenant: connection.tenant,
          product: connection.product,
          clientID: connection.clientID,
          providerName: connection?.idpMetadata?.provider,
          redirectUri: isIdPFlow ? connection?.defaultRedirectUrl : session?.redirect_uri,
          isSAMLFederated,
          isOIDCFederated,
          isIdPFlow,
          acsUrl: session?.requested?.acsUrl,
          entityId: session?.requested?.entityId,
          requestedOIDCFlow: !!session?.requested?.oidc,
          relayState: RelayState,
          issuer,
          profile,
        },
      });

      if (isSAMLFederated) {
        throw err;
      }

      return {
        redirect_url: OAuthErrorResponse({
          error: 'access_denied',
          error_description: traceId ? `${traceId}: ${error_description}` : error_description,
          redirect_uri,
          state: session?.requested?.state,
        }),
        error: `access_denied - ${error_description}`,
      };
    }
  }

  public async oidcAuthzResponse(
    body: OIDCAuthzResponsePayload
  ): Promise<{ redirect_url?: string; response_form?: string; error?: string }> {
    let oidcConnection: OIDCSSORecord | undefined;
    let session: any;
    let isSAMLFederated: boolean | undefined;
    let isOIDCFederated: boolean | undefined;
    let redirect_uri: string | undefined;
    let profile;
    let protocol;
    const login_type = 'sp-initiated';

    const callbackParams = body;

    let RelayState = callbackParams.state || '';
    try {
      metrics.increment('oauthResponse', { protocol: 'oidc', login_type });
      if (!RelayState) {
        throw new JacksonError('State from original request is missing.', 403);
      }

      RelayState = RelayState.replace(relayStatePrefix, '');
      session = await this.sessionStore.get(RelayState);
      if (!session) {
        throw new JacksonError('Unable to validate state from the original request.', 403);
      }

      isSAMLFederated = session && 'samlFederated' in session;
      isOIDCFederated = session && 'oidcFederated' in session;

      protocol = isOIDCFederated ? 'oidc-federation' : isSAMLFederated ? 'saml-federation' : 'oidc';
      if (protocol !== 'oidc') {
        metrics.increment('idfedResponse', { protocol, login_type });
      }
      oidcConnection = await this.connectionStore.get(session.id);

      if (!oidcConnection) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, 'OIDC connection not found.');
      }

      if (!isSAMLFederated) {
        redirect_uri = session && session.redirect_uri;
        if (!redirect_uri) {
          throw new JacksonError('Redirect URL from the authorization request could not be retrieved', 403);
        }

        if (
          redirect_uri &&
          !allowed.redirect(
            redirect_uri,
            oidcConnection.redirectUrl as string[],
            this.opts.openid?.redirectExactMatch
          )
        ) {
          if (isOIDCFederated) {
            if (
              !allowed.redirect(
                redirect_uri,
                session.oidcFederated?.redirectUrl as string[],
                this.opts.openid?.redirectExactMatch
              )
            ) {
              throw new JacksonError('Redirect URL is not allowed.', 403);
            }
          } else {
            throw new JacksonError('Redirect URL is not allowed.', 403);
          }
        }
      }
    } catch (err) {
      metrics.increment(protocol === 'oidc' ? 'oauthResponseError' : 'idfedResponseError', {
        protocol,
        login_type,
      });
      await this.ssoTraces.saveTrace({
        error: getErrorMessage(err),
        context: {
          tenant: session?.requested?.tenant || oidcConnection?.tenant,
          product: session?.requested?.product || oidcConnection?.product,
          clientID: session?.requested?.client_id || oidcConnection?.clientID,
          providerName: oidcConnection?.oidcProvider?.provider,
          acsUrl: session?.requested?.acsUrl,
          entityId: session?.requested?.entityId,
          redirectUri: redirect_uri,
          relayState: RelayState,
          isSAMLFederated,
          isOIDCFederated,
          requestedOIDCFlow: !!session?.requested?.oidc,
          oidcIdPRequest: session?.requested?.oidcIdPRequest,
        },
      });
      // Rethrow err and redirect to Jackson error page
      throw err;
    }

    // Reconstruct the oidcClient, code exchange for token and user profile happens here
    const { discoveryUrl, metadata, clientId, clientSecret } = oidcConnection.oidcProvider;
    const { ssoTraces } = this;
    let tokens: AuthorizationCodeGrantResult | undefined = undefined;
    try {
      const client = (await dynamicImport('openid-client')) as typeof import('openid-client');
      const oidcConfig = await oidcClientConfig({
        discoveryUrl,
        metadata,
        clientId,
        clientSecret,
        ssoTraces: {
          instance: ssoTraces,
          context: {
            tenant: oidcConnection.tenant,
            product: oidcConnection.product,
            clientID: oidcConnection.clientID,
            providerName: oidcConnection.oidcProvider.provider,
            redirectUri: redirect_uri,
            relayState: RelayState,
            isSAMLFederated,
            isOIDCFederated,
            acsUrl: session.requested.acsUrl,
            entityId: session.requested.entityId,
            requestedOIDCFlow: !!session.requested.oidc,
            oidcIdPRequest: session?.requested?.oidcIdPRequest,
          },
        },
      });
      const currentUrl = new URL(
        this.opts.externalUrl + this.opts.oidcPath + '?' + new URLSearchParams(callbackParams)
      );
      tokens = await client.authorizationCodeGrant(oidcConfig, currentUrl, {
        pkceCodeVerifier: session.oidcCodeVerifier,
        expectedNonce: session.oidcNonce,
        expectedState: callbackParams.state,
        idTokenExpected: true,
      });
      profile = await extractOIDCUserProfile(tokens, oidcConfig, session.includeOidcTokensInAssertion);

      if (isSAMLFederated) {
        const { responseForm } = await this.ssoHandler.createSAMLResponse({ profile, session });

        await this.sessionStore.delete(RelayState);

        return { response_form: responseForm };
      }

      const code = await this._buildAuthorizationCode(oidcConnection, profile, session, false);

      const params = { code };

      if (session && session.state) {
        params['state'] = session.state;
      }

      await this.sessionStore.delete(RelayState);

      return { redirect_url: redirect.success(redirect_uri!, params) };
    } catch (err: any) {
      metrics.increment(protocol === 'oidc' ? 'oauthResponseError' : 'idfedResponseError', {
        protocol,
        login_type,
      });
      const { error, error_description, error_uri, session_state, scope, stack } = err;
      const error_message = error_description || getErrorMessage(err);
      this.opts.logger.error(`OIDCResponse error: ${error_message}`);
      const traceId = await this.ssoTraces.saveTrace({
        error: error_message,
        context: {
          tenant: oidcConnection.tenant,
          product: oidcConnection.product,
          clientID: oidcConnection.clientID,
          providerName: oidcConnection.oidcProvider.provider,
          redirectUri: redirect_uri,
          relayState: RelayState,
          isSAMLFederated,
          isOIDCFederated,
          acsUrl: session.requested.acsUrl,
          entityId: session.requested.entityId,
          requestedOIDCFlow: !!session.requested.oidc,
          oidcIdPRequest: session?.requested?.oidcIdPRequest,
          profile,
          error,
          error_description,
          error_uri,
          session_state_from_op_error: session_state,
          scope_from_op_error: scope,
          stack,
          oidcTokenSet: { id_token: tokens?.id_token, access_token: tokens?.access_token },
        },
      });
      if (isSAMLFederated) {
        throw err;
      }
      return {
        redirect_url: OAuthErrorResponse({
          error: (error as OAuthErrorHandlerParams['error']) || 'server_error',
          error_description: traceId ? `${traceId}: ${error_message}` : error_message,
          redirect_uri: redirect_uri!,
          state: session.state,
        }),
        error: `${error} - ${error_message}`,
      };
    }
  }

  // Build the authorization code for the session
  private async _buildAuthorizationCode(
    connection: SAMLSSORecord | OIDCSSORecord,
    profile: any,
    session: any,
    isIdPFlow: boolean
  ) {
    // Store details against a code
    const code = crypto.randomBytes(20).toString('hex');

    const requested = isIdPFlow
      ? {
          isIdPFlow: true,
          tenant: connection.tenant,
          product: connection.product,
          providerName: (connection as SAMLSSORecord).idpMetadata.provider,
        }
      : session
        ? session.requested
        : null;

    const codeVal = {
      profile,
      clientID: connection.clientID,
      clientSecret: connection.clientSecret,
      requested,
      isIdPFlow,
    };

    if (session) {
      codeVal['session'] = session;
    }

    const { hexKey, encVal } = encrypt(codeVal);

    await this.codeStore.put(code, encVal);

    return hexKey + '.' + code;
  }

  /**
   * @openapi
   *
   * /oauth/token:
   *   post:
   *     tags:
   *       - OAuth
   *     summary: Code exchange
   *     operationId: oauth-code-exchange
   *     requestBody:
   *       content:
   *         application/x-www-form-urlencoded:
   *           schema:
   *             required:
   *               - client_id
   *               - client_secret
   *               - code
   *               - grant_type
   *               - redirect_uri
   *             type: object
   *             properties:
   *               grant_type:
   *                 type: string
   *                 description: Grant type should be 'authorization_code'
   *                 default: authorization_code
   *               client_id:
   *                 type: string
   *                 description: Use the client_id returned by the SAML connection API
   *               client_secret:
   *                 type: string
   *                 description: Use the client_secret returned by the SAML connection API
   *               code_verifier:
   *                 type: string
   *                 description: code_verifier against the code_challenge in the authz request (relevant to PKCE flow)
   *               redirect_uri:
   *                 type: string
   *                 description: Redirect URI
   *               code:
   *                 type: string
   *                 description: Code
   *       required: true
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 access_token:
   *                   type: string
   *                 token_type:
   *                   type: string
   *                 expires_in:
   *                   type: string
   *               example:
   *                 access_token: 8958e13053832b5af58fdf2ee83f35f5d013dc74
   *                 token_type: bearer
   *                 expires_in: "300"
   *     x-ory-ratelimit-bucket: polis-public-medium
   */
  public async token(body: OAuthTokenReq, authHeader?: string | null): Promise<OAuthTokenRes> {
    let basic_client_id: string | undefined;
    let basic_client_secret: string | undefined;
    let protocol, login_type;
    const jose = (await dynamicImport('jose')) as typeof import('jose');
    try {
      if (authHeader) {
        // Authorization: Basic {Base64(<client_id>:<client_secret>)}
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        [basic_client_id, basic_client_secret] = credentials.split(':');
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err) {
      // no-op
    }

    const { code, grant_type = 'authorization_code', redirect_uri } = body;
    const client_id = 'client_id' in body ? body.client_id : basic_client_id;
    const client_secret = 'client_secret' in body ? body.client_secret : basic_client_secret;
    const code_verifier = 'code_verifier' in body ? body.code_verifier : undefined;

    metrics.increment('oauthToken');
    let traceContext = {} as SSOTrace['context'];
    try {
      if (grant_type !== 'authorization_code') {
        throw new JacksonError('Unsupported grant_type', 400);
      }

      if (!code) {
        throw new JacksonError('Please specify code', 400);
      }

      const codes = code.split('.');
      if (codes.length !== 2) {
        throw new JacksonError('Invalid code', 403);
      }

      const encCodeVal = await this.codeStore.get(codes[1]);
      if (!encCodeVal) {
        throw new JacksonError('Invalid code', 403);
      }

      const codeVal = decrypt(encCodeVal, codes[0]);

      if (!codeVal || !codeVal.profile) {
        throw new JacksonError('Invalid code', 403);
      }

      const requestedOIDCFlow = !!codeVal.requested?.oidc;
      const isOIDCFederated = !!(codeVal.session && 'oidcFederated' in codeVal.session);
      traceContext = {
        tenant: codeVal.requested?.tenant,
        product: codeVal.requested?.product,
        clientID: client_id || '',
        redirectUri: redirect_uri,
        requestedOIDCFlow,
        isOIDCFederated,
        isIdPFlow: codeVal.requested?.isIdPFlow,
        providerName: codeVal.requested?.providerName,
        acsUrl: codeVal.requested?.acsUrl,
        entityId: codeVal.requested?.entityId,
        oAuthStage: 'token_fetch',
      };
      protocol = codeVal.requested.protocol || 'saml';
      login_type = codeVal.isIdPFlow ? 'idp-initiated' : 'sp-initiated';

      if (codeVal.requested?.redirect_uri) {
        if (redirect_uri !== codeVal.requested.redirect_uri) {
          throw new JacksonError(
            `Invalid request: ${!redirect_uri ? 'redirect_uri missing' : 'redirect_uri mismatch'}`,
            400
          );
        }
      }

      if (codeVal.session?.code_challenge) {
        // PKCE flow
        let cv = code_verifier;
        if (!code_verifier) {
          throw new JacksonError('Invalid code_verifier', 401);
        }

        if (codeVal.session.code_challenge_method?.toLowerCase() === 's256') {
          cv = codeVerifier.encode(code_verifier);
        }

        if (codeVal.session.code_challenge !== cv) {
          throw new JacksonError('Invalid code_verifier', 401);
        }

        // For Federation flow, we need to verify the client_secret
        if (client_id?.startsWith(`${clientIDFederatedPrefix}${clientIDOIDCPrefix}`)) {
          if (
            client_id !== codeVal.session?.oidcFederated?.clientID ||
            client_secret !== codeVal.session?.oidcFederated?.clientSecret
          ) {
            throw new JacksonError('Invalid client_id or client_secret', 401);
          }
        }
      } else if (client_id && client_secret) {
        // check if we have an encoded client_id
        if (client_id !== 'dummy') {
          const sp = getEncodedTenantProduct(client_id);
          if (!sp) {
            // OAuth flow
            if (client_id !== codeVal.clientID || client_secret !== codeVal.clientSecret) {
              throw new JacksonError('Invalid client_id or client_secret', 401);
            }
          } else {
            if (
              !codeVal.isIdPFlow &&
              (sp.tenant !== codeVal.requested?.tenant || sp.product !== codeVal.requested?.product)
            ) {
              throw new JacksonError('Invalid tenant or product', 401);
            }
            // encoded client_id, verify client_secret
            if (client_secret !== this.opts.clientSecretVerifier) {
              throw new JacksonError('Invalid client_secret', 401);
            }
          }
        } else {
          if (client_secret !== this.opts.clientSecretVerifier && client_secret !== codeVal.clientSecret) {
            throw new JacksonError('Invalid client_secret', 401);
          }
        }
      } else if (codeVal && codeVal.session) {
        throw new JacksonError('Please specify client_secret or code_verifier', 401);
      }

      // store details against a token
      const token = crypto.randomBytes(20).toString('hex');

      if (this.opts.flattenRawClaims) {
        codeVal.profile.claims = { ...codeVal.profile.claims, ...codeVal.profile.claims.raw };
        delete codeVal.profile.claims.raw;
      }

      const tokenVal = {
        ...codeVal.profile,
        requested: codeVal.requested,
        clientID: codeVal.clientID,
        login_type,
        protocol,
      };

      let subject = codeVal.profile.claims.id;
      if (this.opts.openid?.subjectPrefix) {
        subject =
          codeVal.requested?.tenant + ':' + codeVal.requested?.product + ':' + codeVal.profile.claims.id;
        if (subject.length > 255) {
          subject = crypto.createHash('sha512').update(subject).digest('hex');
        }
      }

      const requestHasNonce = !!codeVal.requested?.nonce;
      if (requestedOIDCFlow) {
        const { jwtSigningKeys, jwsAlg } = this.opts.openid ?? {};
        if (!jwtSigningKeys || !isJWSKeyPairLoaded(jwtSigningKeys)) {
          throw new JacksonError(GENERIC_ERR_STRING, 500, 'JWT signing keys are not loaded');
        }

        let claims: Record<string, string> = requestHasNonce ? { nonce: codeVal.requested.nonce } : {};
        claims = {
          ...claims,
          requested: codeVal.profile.requested,
          ...codeVal.profile.claims,
          id: subject,
        };
        const signingKey = await loadJWSPrivateKey(jwtSigningKeys.private, jwsAlg!);
        const kid = await computeKid(jwtSigningKeys.public, jwsAlg!);
        const id_token = await new jose.SignJWT(claims)
          .setProtectedHeader({ alg: jwsAlg!, kid })
          .setIssuedAt()
          .setIssuer(this.opts.externalUrl)
          .setSubject(subject)
          .setAudience(tokenVal.requested.client_id)
          .setExpirationTime(`${this.opts.db.ttl}s`) //  identity token only really needs to be valid long enough for it to be verified by the client application.
          .sign(signingKey);
        tokenVal.id_token = id_token;
        tokenVal.claims.sub = subject;
      }

      const { hexKey, encVal } = encrypt(tokenVal);

      await this.tokenStore.put(token, encVal);

      // delete the code
      try {
        await this.codeStore.delete(code);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
      } catch (_err) {
        // ignore error
      }

      const tokenResponse: OAuthTokenRes = {
        access_token: hexKey + '.' + token,
        token_type: 'bearer',
        expires_in: this.opts.db.ttl!,
      };

      if (requestedOIDCFlow) {
        tokenResponse.id_token = tokenVal.id_token;
      }

      return tokenResponse;
    } catch (err: any) {
      metrics.increment('oauthTokenError', { protocol, login_type });
      this.ssoTraces.saveTrace({ error: err.message, context: traceContext });
      throw err;
    }
  }

  /**
   * @openapi
   *
   * /oauth/userinfo:
   *   get:
   *     tags:
   *       - OAuth
   *     summary: Get profile
   *     operationId: oauth-get-profile
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: string
   *                 email:
   *                   type: string
   *                 firstName:
   *                   type: string
   *                 lastName:
   *                   type: string
   *                 roles:
   *                   type: array
   *                   items:
   *                     type: string
   *                 groups:
   *                   type: array
   *                   items:
   *                     type: string
   *                 raw:
   *                   type: object
   *                   properties: {}
   *                 requested:
   *                   type: object
   *                   properties: {}
   *               example:
   *                 id: 32b5af58fdf
   *                 email: jackson@coolstartup.com
   *                 firstName: SAML
   *                 lastName: Jackson
   *                 raw: {}
   *                 requested: {}
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  public async userInfo(token: string): Promise<Profile> {
    const tokens = token.split('.');
    if (tokens.length !== 2) {
      throw new JacksonError('Invalid token', 403);
    }

    const encRsp = await this.tokenStore.get(tokens[1]);
    if (!encRsp) {
      throw new JacksonError('Invalid token', 403);
    }

    const rsp = decrypt(encRsp, tokens[0]);

    const traceContext: SSOTrace['context'] = {
      tenant: rsp.requested?.tenant,
      product: rsp.requested?.product,
      clientID: rsp.clientID,
      isIdPFlow: rsp.requested?.isIdPFlow,
      providerName: rsp.requested?.providerName,
      acsUrl: rsp.requested?.acsUrl,
      entityId: rsp.requested?.entityId,
      oAuthStage: 'userinfo_fetch',
    };

    metrics.increment('oauthUserInfo');

    if (!rsp || !rsp.claims) {
      metrics.increment('oauthUserInfoError', { protocol: rsp.protocol, login_type: rsp.login_type });
      this.ssoTraces.saveTrace({ error: 'Invalid token', context: traceContext });
      throw new JacksonError('Invalid token', 403);
    }

    return { ...rsp.claims, requested: rsp.requested };
  }
}
