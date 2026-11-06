import saml from '@boxyhq/saml20';
import crypto from 'crypto';
import { promisify } from 'util';
import { deflateRaw } from 'zlib';
import type { SAMLProfile } from '@boxyhq/saml20/dist/typings';

import type {
  Storable,
  SAMLSSORecord,
  OIDCSSORecord,
  IdentityFederationApp,
  SSOTracesInstance,
  SSOTrace,
  JacksonOptionWithRequiredLogger,
} from '../typings';
import { getDefaultCertificate } from '../saml/x509';
import * as dbutils from '../db/utils';
import { JacksonError } from './error';
import { dynamicImport, GENERIC_ERR_STRING, IndexNames } from './utils';
import { relayStatePrefix } from './utils';
import * as redirect from './oauth/redirect';
import * as allowed from './oauth/allowed';
import { oidcClientConfig } from './oauth/oidc-client';

const deflateRawAsync = promisify(deflateRaw);

export class SSOHandler {
  private connection: Storable;
  private session: Storable;
  private opts: JacksonOptionWithRequiredLogger;

  constructor({
    connection,
    session,
    opts,
  }: {
    connection: Storable;
    session: Storable;
    opts: JacksonOptionWithRequiredLogger;
  }) {
    this.connection = connection;
    this.session = session;
    this.opts = opts;
  }

  // If there are multiple connections for the given tenant and product, return the url to the IdP selection page
  // If idp_hint is provided, return the connection with the matching clientID
  // If there is only one connection, return the connection
  async resolveConnection(params: {
    authFlow: 'oauth' | 'saml' | 'idp-initiated';
    originalParams: Record<string, any>;
    tenant?: string;
    product?: string;
    entityId?: string;
    iss?: string;
    idp_hint?: string;
    idFedAppId?: string;
    fedType?: string;
    thirdPartyLogin?: { idpInitiatorType?: 'oidc' | 'saml'; iss?: string; target_link_uri?: string };
    tenants?: string[]; // Only used for SAML IdP initiated flow
    ssoTraces?: { instance: SSOTracesInstance; context: SSOTrace['context'] };
  }): Promise<
    { connection: SAMLSSORecord | OIDCSSORecord } | { redirectUrl: string } | { postForm: string }
  > {
    const {
      authFlow,
      originalParams,
      tenant,
      product,
      idp_hint,
      entityId,
      tenants,
      idFedAppId = '',
      fedType = '',
      thirdPartyLogin = null,
      ssoTraces,
    } = params;

    let connections: (SAMLSSORecord | OIDCSSORecord)[] | null = null;
    const noSSOConnectionErrMessage = 'No SSO connection found.';

    // If an IdP is specified, find the connection for that IdP
    if (idp_hint) {
      const connection = await this.connection.get(idp_hint);

      if (!connection) {
        throw new JacksonError(GENERIC_ERR_STRING, 403, noSSOConnectionErrMessage);
      }

      return { connection };
    }

    // Find SAML connections for the app
    if (tenants && tenants.length > 0 && product) {
      const result = await Promise.all(
        tenants.map((tenant) =>
          this.connection.getByIndex({
            name: IndexNames.TenantProduct,
            value: dbutils.keyFromParts(tenant, product),
          })
        )
      );

      connections = result.flatMap((r) => r.data);
    } else if (tenant && product) {
      const result = await this.connection.getByIndex({
        name: IndexNames.TenantProduct,
        value: dbutils.keyFromParts(tenant, product),
      });

      connections = result.data;
    } else if (entityId) {
      const result = await this.connection.getByIndex({ name: IndexNames.EntityID, value: entityId });

      connections = result.data;
    }

    if (!connections || connections.length === 0) {
      throw new JacksonError(GENERIC_ERR_STRING, 403, noSSOConnectionErrMessage);
    }

    // Third party login from an oidcProvider, here we match the connection from the iss param
    if (thirdPartyLogin?.idpInitiatorType === 'oidc') {
      const oidcConnections = connections.filter(
        (connection) => 'oidcProvider' in connection
      ) as OIDCSSORecord[];

      for (const { oidcProvider, ...rest } of oidcConnections) {
        const connection = { oidcProvider, ...rest };
        const { discoveryUrl, metadata, clientId, clientSecret } = oidcProvider;
        const oidcConfig = await oidcClientConfig({
          discoveryUrl,
          metadata,
          clientId,
          clientSecret,
          ssoTraces: ssoTraces!,
        });

        if (oidcConfig.serverMetadata().issuer === thirdPartyLogin.iss) {
          if (thirdPartyLogin.target_link_uri) {
            if (
              !allowed.redirect(
                thirdPartyLogin.target_link_uri,
                connection.redirectUrl as string[],
                this.opts.openid?.redirectExactMatch
              )
            ) {
              throw new JacksonError('target_link_uri is not allowed');
            }
          }
          return { connection };
        }
      }
      // No match found for iss
      throw new JacksonError(GENERIC_ERR_STRING, 403, noSSOConnectionErrMessage);
    }

    // If more than one, redirect to the connection selection page
    if (connections.length > 1) {
      const url = new URL(`${this.opts.externalUrl}${this.opts.idpDiscoveryPath}`);

      // SP initiated flow
      if (['oauth', 'saml'].includes(authFlow)) {
        const qps = { authFlow: 'sp-initiated', idFedAppId, fedType, ...originalParams };
        if (tenant && product && fedType !== 'oidc') {
          qps['tenant'] = tenant;
          qps['product'] = product;
        }
        const params = new URLSearchParams(qps);

        return { redirectUrl: `${url}?${params}` };
      }

      // IdP initiated flow
      if (authFlow === 'idp-initiated') {
        if (entityId) {
          const params = new URLSearchParams({ entityId, authFlow });

          try {
            const postForm = saml.createPostForm(`${this.opts.idpDiscoveryPath}?${params}`, [
              { name: 'SAMLResponse', value: originalParams.SAMLResponse },
            ]);
            return { postForm };
          } catch (err: any) {
            throw new JacksonError(
              GENERIC_ERR_STRING,
              403,
              `SAML IdP initiated flow error creating app select form: ${err.message}`
            );
          }
        }
      }
    }

    // If only one, use that connection
    return { connection: connections[0] };
  }

  async createSAMLRequest({
    connection,
    requestParams,
    mappings,
  }: {
    connection: SAMLSSORecord;
    requestParams: Record<string, any>;
    mappings: IdentityFederationApp['mappings'];
  }) {
    try {
      // We have a connection now, so we can create the SAML request
      const certificate = await getDefaultCertificate();

      const { sso } = connection.idpMetadata;

      let ssoUrl;
      let post = false;

      if ('redirectUrl' in sso) {
        ssoUrl = sso.redirectUrl;
      } else if ('postUrl' in sso) {
        ssoUrl = sso.postUrl;
        post = true;
      }

      const samlRequest = saml.request({
        ssoUrl,
        entityID: connection.samlAudienceOverride ? connection.samlAudienceOverride : this.opts.samlAudience!,
        callbackUrl: connection.acsUrlOverride ? connection.acsUrlOverride : (this.opts.acsUrl as string),
        signingKey: certificate.privateKey,
        publicKey: certificate.publicKey,
        forceAuthn: !!connection.forceAuthn,
        identifierFormat: connection.identifierFormat
          ? connection.identifierFormat
          : 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      });

      const relayState = await this.createSession({
        requestId: samlRequest.id,
        requested: { ...requestParams, client_id: connection.clientID },
        mappings,
      });

      let redirectUrl;
      let authorizeForm;

      // Decide whether to use HTTP Redirect or HTTP POST binding
      if (!post) {
        redirectUrl = redirect.success(ssoUrl, {
          RelayState: relayState,
          SAMLRequest: Buffer.from(await deflateRawAsync(samlRequest.request)).toString('base64'),
        });
      } else {
        authorizeForm = saml.createPostForm(ssoUrl, [
          { name: 'RelayState', value: relayState },
          { name: 'SAMLRequest', value: Buffer.from(samlRequest.request).toString('base64') },
        ]);
      }

      return { redirect_url: redirectUrl, authorize_form: authorizeForm };
    } catch (err: any) {
      throw new JacksonError(GENERIC_ERR_STRING, 400, `Error creating SAML request: ${err.message}`);
    }
  }

  async createOIDCRequest({
    connection,
    requestParams,
    mappings,
    includeOidcTokensInAssertion,
    ssoTraces,
  }: {
    connection: OIDCSSORecord;
    requestParams: Record<string, any>;
    mappings: IdentityFederationApp['mappings'];
    includeOidcTokensInAssertion?: boolean;
    ssoTraces: { instance: SSOTracesInstance; context: SSOTrace['context'] };
  }) {
    if (!this.opts.oidcPath) {
      throw new JacksonError(GENERIC_ERR_STRING, 400, 'OpenID response handler path (oidcPath) is not set');
    }

    const { discoveryUrl, metadata, clientId, clientSecret } = connection.oidcProvider;

    try {
      const client = (await dynamicImport('openid-client')) as typeof import('openid-client');
      const oidcConfig = await oidcClientConfig({
        discoveryUrl,
        metadata,
        clientId,
        clientSecret,
        ssoTraces,
      });
      const oidcCodeVerifier = client.randomPKCECodeVerifier();
      const code_challenge = await client.calculatePKCECodeChallenge(oidcCodeVerifier);
      const oidcNonce = client.randomNonce();
      const standardScopes = this.opts.openid?.requestProfileScope
        ? ['openid', 'email', 'profile']
        : ['openid', 'email'];

      const relayState = await this.createSession({
        requestId: connection.clientID,
        requested: requestParams,
        oidcCodeVerifier,
        oidcNonce,
        mappings,
        includeOidcTokensInAssertion,
      });

      const ssoUrl = client.buildAuthorizationUrl(oidcConfig, {
        scope: standardScopes
          .filter((value, index, self) => self.indexOf(value) === index) // filter out duplicates
          .join(' '),
        code_challenge,
        code_challenge_method: 'S256',
        state: relayState,
        nonce: oidcNonce,
        redirect_uri: this.opts.externalUrl + this.opts.oidcPath,
      }).href;

      return { redirect_url: ssoUrl, authorize_form: null };
    } catch (err: any) {
      throw new JacksonError(GENERIC_ERR_STRING, 400, `Error creating OIDC request: ${err.message}`);
    }
  }

  createSAMLResponse = async ({ profile, session }: { profile: SAMLProfile; session: any }) => {
    const certificate = await getDefaultCertificate();

    const mappedClaims = profile.claims;
    if (session.mappings) {
      session.mappings.forEach((elem) => {
        const key = elem.key;
        const value = elem.value;
        if (mappedClaims.raw[value]) {
          mappedClaims.raw[key] = mappedClaims.raw[value];
        }
      });
      session.mappings.forEach((elem) => {
        const value = elem.value;
        delete mappedClaims.raw[value];
      });
    }

    try {
      const responseSigned = await saml.createSAMLResponse({
        audience: session.requested.entityId,
        acsUrl: session.requested.acsUrl,
        requestId: session.requested.id,
        issuer: session.requested.fedAppSamlAudienceOverride || this.opts.samlAudience!,
        claims: mappedClaims,
        ...certificate,
        flattenArray: true,
        ttlInMinutes: session.oidcFederated?.ttlInMinutes ?? session.requested?.ttlInMinutes,
      });

      const params: { name: string; value: string }[] = [];

      if (session.requested.relayState) {
        params.push({ name: 'RelayState', value: session.requested.relayState });
      }

      params.push({ name: 'SAMLResponse', value: Buffer.from(responseSigned).toString('base64') });

      const responseForm = saml.createPostForm(session.requested.acsUrl, params);

      return { responseForm };
    } catch (err: any) {
      // TODO: Instead send saml response with status code
      throw new JacksonError(GENERIC_ERR_STRING, 403, `Error creating SAML Response: ${err.message}`);
    }
  };

  // Create a new session to store SP request information
  private createSession = async ({
    requestId,
    requested,
    oidcCodeVerifier,
    oidcNonce,
    mappings,
    includeOidcTokensInAssertion,
  }: {
    requestId: string;
    requested: any;
    oidcCodeVerifier?: string;
    oidcNonce?: string;
    mappings: IdentityFederationApp['mappings'];
    includeOidcTokensInAssertion?: boolean;
  }) => {
    const sessionId = crypto.randomBytes(16).toString('hex');

    const session = { id: requestId, requested, samlFederated: true, mappings };

    if (oidcCodeVerifier) {
      session['oidcCodeVerifier'] = oidcCodeVerifier;
    }

    if (oidcNonce) {
      session['oidcNonce'] = oidcNonce;
    }

    if (includeOidcTokensInAssertion !== undefined) {
      session['includeOidcTokensInAssertion'] = includeOidcTokensInAssertion;
    }

    await this.session.put(sessionId, session);

    return `${relayStatePrefix}${sessionId}`;
  };
}
