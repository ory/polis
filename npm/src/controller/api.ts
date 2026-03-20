import * as dbutils from '../db/utils';
import * as metrics from '../opentelemetry/metrics';
import {
  GetConfigQuery,
  GetConnectionsQuery,
  DelConnectionsQuery,
  IConnectionAPIController,
  Storable,
  SAMLSSOConnectionWithEncodedMetadata,
  SAMLSSOConnectionWithRawMetadata,
  OIDCSSOConnectionWithDiscoveryUrl,
  OIDCSSOConnectionWithMetadata,
  JacksonOption,
  SAMLSSORecord,
  OIDCSSORecord,
  GetIDPEntityIDBody,
  IEventController,
  UpdateSAMLConnectionParams,
  UpdateOIDCConnectionParams,
  GetByProductParams,
  Index,
} from '../typings';
import { JacksonError } from './error';
import { IndexNames, appID, transformConnections, transformConnection, isConnectionActive } from './utils';
import oidcConnection from './connection/oidc';
import samlConnection from './connection/saml';

export class ConnectionAPIController implements IConnectionAPIController {
  private connectionStore: Storable;
  private opts: JacksonOption;
  private eventController: IEventController;

  constructor({ connectionStore, opts, eventController }) {
    this.connectionStore = connectionStore;
    this.opts = opts;
    this.eventController = eventController;
  }

  /**
   * @openapi
   * components:
   *   schemas:
   *     Connection:
   *       type: object
   *       properties:
   *         clientID:
   *           type: string
   *           description: Connection clientID
   *         clientSecret:
   *           type: string
   *           description: Connection clientSecret
   *         name:
   *           type: string
   *           description: Connection name
   *         label:
   *           type: string
   *           description: Connection label
   *         description:
   *           type: string
   *           description: Connection description
   *         redirectUrl:
   *           type: array
   *           items:
   *             type: string
   *           description: A list of allowed redirect URLs
   *         defaultRedirectUrl:
   *           type: string
   *           description: The redirect URL to use in the IdP login flow
   *         tenant:
   *           type: string
   *           description: Connection tenant
   *         product:
   *           type: string
   *           description: Connection product
   *         idpMetadata:
   *           type: object
   *           properties: {}
   *           description: SAML IdP metadata
   *         oidcProvider:
   *           type: object
   *           properties: {}
   *           description: OIDC IdP metadata
   *         deactivated:
   *           type: boolean
   *           description: Connection status
   *         sortOrder:
   *           type: number
   *           description: Connection sort order
   *         acsUrlOverride:
   *           type: string
   *           description: Override the global ACS URL on a per connection basis
   *         samlAudienceOverride:
   *           type: string
   *           description: Override the global SAML Audience on a per connection basis
   *       example:
   *         idpMetadata:
   *           sso:
   *             postUrl: https://dev-20901260.okta.com/app/dev-20901260_jacksonnext_1/xxxxxxxxxxxsso/saml
   *             redirectUrl: https://dev-20901260.okta.com/app/dev-20901260_jacksonnext_1/xxxxxxxxxxxsso/saml
   *           entityID: http://www.okta.com/xxxxxxxxxxxxx
   *           thumbprint: Eo+eUi3UM3XIMkFFtdVK3yJ5vO9f7YZdasdasdad
   *           loginType: idp
   *           provider: okta.com
   *         defaultRedirectUrl: http://localhost:3000/default
   *         redirectUrl:
   *           - http://localhost:3000/default
   *         tenant: example.com
   *         product: API Engine
   *         name: Hoppscotch-SP
   *         description: SP for example.com
   *         clientID: Xq8AJt3yYAxmXizsCWmUBDRiVP1iTC8Y/otnvFIMitk
   *         clientSecret: 00e3e11a3426f97d8000000738300009130cd45419c5943
   *         deactivated: false
   *     validationErrorsPost:
   *       description: Please provide rawMetadata or encodedRawMetadata | Please provide a defaultRedirectUrl | Please provide redirectUrl | redirectUrl is invalid | Exceeded maximum number of allowed redirect urls | defaultRedirectUrl is invalid | Please provide tenant | Please provide product | Please provide a friendly name | Description should not exceed 100 characters | Strategy&#58; xxxx not supported | Please provide the clientId from OpenID Provider | Please provide the clientSecret from OpenID Provider | Please provide the discoveryUrl for the OpenID Provider
   *     validationErrorsPatch:
   *       description: Please provide clientID/clientSecret | clientSecret mismatch | Tenant/Product config mismatch with IdP metadata | Description should not exceed 100 characters| redirectUrl is invalid | Exceeded maximum number of allowed redirect urls | defaultRedirectUrl is invalid | Tenant/Product config mismatch with OIDC Provider metadata
   *   responses:
   *     200Get:
   *       description: Success
   *       content:
   *         application/json:
   *           schema:
   *             type: array
   *             items:
   *               $ref: "#/components/schemas/Connection"
   *     400Get:
   *       description: Please provide a `product`.
   *       content: {}
   *     401Get:
   *       description: Unauthorized
   *       content: {}
   *     200GetByProduct:
   *       description: Success
   *       content:
   *          application/json:
   *           schema:
   *             type: array
   *             items:
   *               $ref: "#/components/schemas/Connection"
   *   parameters:
   *     tenantParamGet:
   *       name: tenant
   *       in: query
   *       description: Tenant
   *       required: true
   *       schema:
   *         type: string
   *     productParamGet:
   *       name: product
   *       in: query
   *       description: Product
   *       required: true
   *       schema:
   *         type: string
   *     clientIDParamGet:
   *       name: clientID
   *       in: query
   *       description: Client ID (Optional if tenant/product provided)
   *       schema:
   *         type: string
   *     strategyParamGet:
   *       name: strategy
   *       in: query
   *       description: Strategy which can help to filter connections with tenant/product query
   *       schema:
   *         type: string
   *     sortParamGet:
   *       name: sort
   *       in: query
   *       description: If present, the connections will be sorted by `sortOrder`. It won't consider if pagination is used.
   *       schema:
   *         type: string
   *     clientIDDel:
   *       name: clientID
   *       in: query
   *       description: Client ID (Optional if tenant/product provided)
   *       schema:
   *         type: string
   *     clientSecretDel:
   *       name: clientSecret
   *       in: query
   *       description: Client Secret (Optional if tenant/product provided)
   *       schema:
   *         type: string
   *     tenantDel:
   *       name: tenant
   *       in: query
   *       description: Tenant (Optional if clientID/Secret provided)
   *       schema:
   *         type: string
   *     productDel:
   *       name: product
   *       in: query
   *       description: Product (Optional if clientID/Secret provided)
   *       schema:
   *         type: string
   *     strategyDel:
   *       name: strategy
   *       in: query
   *       description: Strategy which can help to filter connections with tenant/product query
   *       schema:
   *         type: string
   *   securitySchemes:
   *     apiKey:
   *       type: apiKey
   *       name: Authorization
   *       in: header
   *
   */

  /**
   *
   * @openapi
   * /api/v1/sso:
   *   post:
   *     tags:
   *       - Single Sign-On
   *     summary: Create SSO connection
   *     operationId: create-sso-connection
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             required:
   *               - defaultRedirectUrl
   *               - product
   *               - redirectUrl
   *               - tenant
   *             type: object
   *             properties:
   *               name:
   *                 type: string
   *                 description: Name of connection
   *               label:
   *                 type: string
   *                 description: An internal label to identify the connection
   *               description:
   *                 type: string
   *                 description: A short description for the connection not more than 100 characters
   *               encodedRawMetadata:
   *                 type: string
   *                 description: Base64 encoding of the XML metadata
   *               rawMetadata:
   *                 type: string
   *                 description: Raw XML metadata
   *               metadataUrl:
   *                 type: string
   *                 description: URL containing raw XML metadata
   *               defaultRedirectUrl:
   *                 type: string
   *                 description: The redirect URL to use in the IdP login flow
   *               redirectUrl:
   *                 type: array
   *                 items:
   *                   type: string
   *                 description: JSON encoded array containing a list of allowed redirect URLs
   *               tenant:
   *                 type: string
   *                 description: Tenant
   *               product:
   *                 type: string
   *                 description: Product
   *               oidcDiscoveryUrl:
   *                 type: string
   *                 description: well-known URL where the OpenID Provider configuration is exposed
   *               oidcMetadata:
   *                 type: string
   *                 description: metadata (JSON) for the OpenID Provider in the absence of discoveryUrl
   *               oidcClientId:
   *                 type: string
   *                 description: clientId of the application set up on the OpenID Provider
   *               oidcClientSecret:
   *                 type: string
   *                 description: clientSecret of the application set up on the OpenID Provider
   *               sortOrder:
   *                 type: number
   *                 description: Indicate the position of the connection in the IdP selection screen
   *               acsUrlOverride:
   *                 type: string
   *                 description: Override the global ACS URL on a per connection basis
   *               samlAudienceOverride:
   *                 type: string
   *                 description: Override the global SAML Audience on a per connection basis
   *               forceAuthn:
   *                 type: boolean
   *                 description: Require a new authentication instead of reusing an existing session.
   *       required: true
   *     responses:
   *       "200":
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/Connection"
   *       "400":
   *         $ref: "#/components/schemas/validationErrorsPost"
   *       "401":
   *         description: Unauthorized
   *     x-ory-ratelimit-bucket: polis-public-medium
   */
  public async createSAMLConnection(
    body: SAMLSSOConnectionWithEncodedMetadata | SAMLSSOConnectionWithRawMetadata
  ): Promise<SAMLSSORecord> {
    metrics.increment('createConnection');

    const connection = await samlConnection.create(body, this.connectionStore);

    await this.eventController.notify('sso.created', connection);

    return connection;
  }

  // For backwards compatibility
  public async config(
    ...args: Parameters<ConnectionAPIController['createSAMLConnection']>
  ): Promise<SAMLSSORecord> {
    return this.createSAMLConnection(...args);
  }

  public async createOIDCConnection(
    body: OIDCSSOConnectionWithDiscoveryUrl | OIDCSSOConnectionWithMetadata
  ): Promise<OIDCSSORecord> {
    metrics.increment('createConnection');

    if (!this.opts.oidcPath) {
      throw new JacksonError('Please set OpenID response handler path (oidcPath) on Jackson', 500);
    }

    const connection = await oidcConnection.create(body, this.connectionStore);

    await this.eventController.notify('sso.created', connection);

    return connection;
  }

  /**
   * @openapi
   * /api/v1/sso:
   *   patch:
   *     tags:
   *       - Single Sign-On
   *     summary: Update SSO Connection
   *     operationId: update-sso-connection
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             required:
   *               - clientID
   *               - clientSecret
   *               - product
   *               - tenant
   *             type: object
   *             properties:
   *               clientID:
   *                 type: string
   *                 description: Client ID for the connection
   *               clientSecret:
   *                 type: string
   *                 description: Client Secret for the connection
   *               name:
   *                 type: string
   *                 description: Name/identifier for the connection
   *               label:
   *                 type: string
   *                 description: An internal label to identify the connection
   *               description:
   *                 type: string
   *                 description: A short description for the connection not more than 100 characters
   *               encodedRawMetadata:
   *                 type: string
   *                 description: Base64 encoding of the XML metadata
   *               rawMetadata:
   *                 type: string
   *                 description: Raw XML metadata
   *               metadataUrl:
   *                 type: string
   *                 description: URL containing raw XML metadata
   *               oidcDiscoveryUrl:
   *                 type: string
   *                 description: well-known URL where the OpenID Provider configuration is exposed
   *               oidcMetadata:
   *                 type: string
   *                 description: metadata (JSON) for the OpenID Provider in the absence of discoveryUrl
   *               oidcClientId:
   *                 type: string
   *                 description: clientId of the application set up on the OpenID Provider
   *               oidcClientSecret:
   *                 type: string
   *                 description: clientSecret of the application set up on the OpenID Provider
   *               defaultRedirectUrl:
   *                 type: string
   *                 description: The redirect URL to use in the IdP login flow
   *               redirectUrl:
   *                 type: array
   *                 items:
   *                   type: string
   *                 description: JSON encoded array containing a list of allowed redirect URLs
   *               tenant:
   *                 type: string
   *                 description: Tenant
   *               product:
   *                 type: string
   *                 description: Product
   *               deactivated:
   *                 type: boolean
   *                 description: Connection status
   *               sortOrder:
   *                 type: number
   *                 description: Indicate the position of the connection in the IdP selection screen
   *               acsUrlOverride:
   *                 type: string
   *                 description: Override the global ACS URL on a per connection basis
   *               samlAudienceOverride:
   *                 type: string
   *                 description: Override the global SAML Audience on a per connection basis
   *               forceAuthn:
   *                 type: boolean
   *                 description: Require a new authentication instead of reusing an existing session.
   *       required: true
   *     responses:
   *       "200":
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/Connection"
   *       "204":
   *         description: Success
   *         content: {}
   *       "400":
   *         $ref: "#/components/schemas/validationErrorsPatch"
   *       "401":
   *         description: Unauthorized
   *         content: {}
   *       "500":
   *         description: Please set OpenID response handler path (oidcPath) on Jackson
   *         content: {}
   *     x-ory-ratelimit-bucket: polis-public-medium
   */
  public async updateSAMLConnection(body: UpdateSAMLConnectionParams): Promise<SAMLSSORecord> {
    const connection = await samlConnection.update(
      body,
      this.connectionStore,
      this.getConnections.bind(this)
    );

    if ('deactivated' in body) {
      if (isConnectionActive(connection)) {
        await this.eventController.notify('sso.activated', connection);
      } else {
        await this.eventController.notify('sso.deactivated', connection);
      }
    }

    return connection;
  }

  // For backwards compatibility
  public async updateConfig(
    ...args: Parameters<ConnectionAPIController['updateSAMLConnection']>
  ): Promise<void> {
    await this.updateSAMLConnection(...args);
  }

  public async updateOIDCConnection(body: UpdateOIDCConnectionParams): Promise<OIDCSSORecord> {
    if (!this.opts.oidcPath) {
      throw new JacksonError('Please set OpenID response handler path (oidcPath) on Jackson', 500);
    }

    const connection = await oidcConnection.update(
      body,
      this.connectionStore,
      this.getConnections.bind(this)
    );

    if ('deactivated' in body) {
      if (isConnectionActive(connection)) {
        await this.eventController.notify('sso.activated', connection);
      } else {
        await this.eventController.notify('sso.deactivated', connection);
      }
    }

    return connection;
  }

  public getIDPEntityID(body: GetIDPEntityIDBody): string {
    const tenant = 'tenant' in body ? body.tenant : undefined;
    const product = 'product' in body ? body.product : undefined;
    if (!tenant || !product) {
      throw new JacksonError('Please provide `tenant` and `product`.', 400);
    } else {
      return `${this.opts.samlAudience}/${appID(tenant, product)}`;
    }
  }

  /**
   * @openapi
   * /api/v1/sso:
   *   get:
   *     tags:
   *       - Single Sign-On
   *     summary: Get SSO Connections
   *     operationId: get-connections
   *     parameters:
   *       - name: tenant
   *         in: query
   *         description: Tenant
   *         required: true
   *         schema:
   *           type: string
   *       - name: product
   *         in: query
   *         description: Product
   *         required: true
   *         schema:
   *           type: string
   *       - name: clientID
   *         in: query
   *         description: Client ID (Optional if tenant/product provided)
   *         schema:
   *           type: string
   *       - name: strategy
   *         in: query
   *         description: Strategy which can help to filter connections with tenant/product query
   *         schema:
   *           type: string
   *       - name: sort
   *         in: query
   *         description: If present, the connections will be sorted by `sortOrder`. It won't consider if pagination is used.
   *         schema:
   *           type: string
   *     responses:
   *      "200":
   *        $ref: '#/components/responses/200Get'
   *      "400":
   *        $ref: '#/components/responses/400Get'
   *      "401":
   *        $ref: '#/components/responses/401Get'
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  public async getConnections(body: GetConnectionsQuery): Promise<Array<SAMLSSORecord | OIDCSSORecord>> {
    const clientID = 'clientID' in body ? body.clientID : undefined;
    const tenant = 'tenant' in body ? body.tenant : undefined;
    const product = 'product' in body ? body.product : undefined;
    const strategy = 'strategy' in body ? body.strategy : undefined;
    const entityId = 'entityId' in body ? body.entityId : undefined;

    metrics.increment('getConnections');

    let connections: (SAMLSSORecord | OIDCSSORecord)[] | null = null;

    // Fetch connections by entityId
    if (entityId) {
      const result = await this.connectionStore.getByIndex({
        name: IndexNames.EntityID,
        value: entityId,
      });

      if (!result || typeof result !== 'object') {
        connections = [];
      } else {
        connections = result.data;
      }
    }

    // Fetch connections by clientID
    else if (clientID) {
      const result = await this.connectionStore.get(clientID);

      if (!result || typeof result !== 'object') {
        connections = [];
      } else {
        connections = [result];
      }
    }

    // Fetch connections by multiple tenants
    else if (tenant && product && Array.isArray(tenant)) {
      const tenants = tenant.filter((t) => t).filter((t, i, a) => a.indexOf(t) === i);

      const result = await Promise.all(
        tenants.map(async (t) =>
          this.connectionStore.getByIndex({
            name: IndexNames.TenantProduct,
            value: dbutils.keyFromParts(t, product),
          })
        )
      );

      if (!result || !result.length) {
        connections = [];
      } else {
        connections = result.flatMap((r) => r.data);
      }
    }

    // Fetch connections by tenant and product
    else if (tenant && product && !Array.isArray(tenant)) {
      const result = await this.connectionStore.getByIndex({
        name: IndexNames.TenantProduct,
        value: dbutils.keyFromParts(tenant, product),
      });

      if (!result || !result.data.length) {
        connections = [];
      } else {
        connections = result.data;
      }

      // Filter connections by strategy
      if (connections && connections.length > 0 && strategy) {
        connections = connections.filter((connection) => {
          if (strategy === 'saml') {
            return 'idpMetadata' in connection;
          }

          if (strategy === 'oidc') {
            return 'oidcProvider' in connection;
          }

          return false;
        });
      }
    }

    if (connections) {
      const sort = 'sort' in body ? body.sort : false;

      if (sort) {
        connections.sort((a, b) => (b.sortOrder || 0) - (a.sortOrder || 0));
      }

      return transformConnections(connections);
    }

    throw new JacksonError('Please provide `clientID` or `tenant` and `product`.', 400);
  }

  public async getConfig(body: GetConfigQuery): Promise<SAMLSSORecord | Record<string, never>> {
    const clientID = 'clientID' in body ? body.clientID : undefined;
    const tenant = 'tenant' in body ? body.tenant : undefined;
    const product = 'product' in body ? body.product : undefined;

    metrics.increment('getConnections');

    if (clientID) {
      const samlConfig = await this.connectionStore.get(clientID);

      return samlConfig || {};
    }

    if (tenant && product) {
      const samlConfigs = (
        await this.connectionStore.getByIndex({
          name: IndexNames.TenantProduct,
          value: dbutils.keyFromParts(tenant, product),
        })
      ).data;

      if (!samlConfigs || !samlConfigs.length) {
        return {};
      }

      return { ...samlConfigs[0] };
    }

    throw new JacksonError('Please provide `clientID` or `tenant` and `product`.', 400);
  }

  /**
   * @openapi
   * /api/v1/sso:
   *   delete:
   *     tags:
   *       - Single Sign-On
   *     summary: Delete SSO Connections
   *     operationId: delete-sso-connection
   *     parameters:
   *       - name: clientID
   *         in: query
   *         description: Client ID (Optional if tenant/product provided)
   *         schema:
   *           type: string
   *       - name: clientSecret
   *         in: query
   *         description: Client Secret (Optional if tenant/product provided)
   *         schema:
   *           type: string
   *       - name: tenant
   *         in: query
   *         description: Tenant (Optional if clientID/Secret provided)
   *         schema:
   *           type: string
   *       - name: product
   *         in: query
   *         description: Product (Optional if clientID/Secret provided)
   *         schema:
   *           type: string
   *       - name: strategy
   *         in: query
   *         description: Strategy which can help to filter connections with tenant/product query
   *         schema:
   *           type: string
   *     responses:
   *       '200':
   *         description: Success
   *       '400':
   *         description: clientSecret mismatch | Please provide `clientID` and `clientSecret` or `tenant` and `product`.
   *       '401':
   *         description: Unauthorized
   *     x-ory-ratelimit-bucket: polis-public-medium
   */
  public async deleteConnections(body: DelConnectionsQuery): Promise<void> {
    const clientID = 'clientID' in body ? body.clientID : undefined;
    const clientSecret = 'clientSecret' in body ? body.clientSecret : undefined;
    const tenant = 'tenant' in body ? body.tenant : undefined;
    const product = 'product' in body ? body.product : undefined;
    const strategy = 'strategy' in body ? body.strategy : undefined;

    metrics.increment('deleteConnections');

    if (clientID && clientSecret) {
      const connection = await this.connectionStore.get(clientID);

      if (!connection) {
        return;
      }

      if (connection.clientSecret === clientSecret) {
        await this.connectionStore.delete(clientID);
        await this.eventController.notify('sso.deleted', transformConnection(connection));
      } else {
        throw new JacksonError('clientSecret mismatch', 400);
      }

      return;
    }

    if (tenant && product) {
      const connections = (
        await this.connectionStore.getByIndex({
          name: IndexNames.TenantProduct,
          value: dbutils.keyFromParts(tenant, product),
        })
      ).data;

      if (!connections || !connections.length) {
        return;
      }

      // filter if strategy is passed
      const filteredConnections = strategy
        ? connections.filter((connection) => {
            if (strategy === 'saml') {
              if (connection.idpMetadata) {
                return true;
              }
            }
            if (strategy === 'oidc') {
              if (connection.oidcProvider) {
                return true;
              }
            }
            return false;
          })
        : connections;

      for (const conf of transformConnections(filteredConnections)) {
        await this.connectionStore.delete(conf.clientID);
        await this.eventController.notify('sso.deleted', conf);
      }

      return;
    }

    throw new JacksonError('Please provide `clientID` and `clientSecret` or `tenant` and `product`.', 400);
  }

  public async deleteConfig(body: DelConnectionsQuery): Promise<void> {
    await this.deleteConnections({ ...body, strategy: 'saml' });
  }

  /**
   * @openapi
   * /api/v1/sso/product:
   *   get:
   *     tags:
   *       - Single Sign-On
   *     summary: Get SSO Connections by product
   *     operationId: get-connections-by-product
   *     parameters:
   *       - $ref: '#/components/parameters/productParamGet'
   *       - $ref: '#/components/parameters/pageOffset'
   *       - $ref: '#/components/parameters/pageLimit'
   *       - $ref: '#/components/parameters/pageToken'
   *     responses:
   *      '200':
   *        $ref: '#/components/responses/200GetByProduct'
   *      '400':
   *        $ref: '#/components/responses/400Get'
   *      '401':
   *        $ref: '#/components/responses/401Get'
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  public async getConnectionsByProduct(
    body: GetByProductParams
  ): Promise<{ data: (SAMLSSORecord | OIDCSSORecord)[]; pageToken?: string }> {
    const { product, pageOffset, pageLimit, pageToken } = body;

    if (!product) {
      throw new JacksonError('Please provide a `product`.', 400);
    }

    const connections = await this.connectionStore.getByIndex(
      {
        name: IndexNames.Product,
        value: product,
      },
      pageOffset,
      pageLimit,
      pageToken
    );

    return { data: transformConnections(connections.data), pageToken };
  }

  public async getCount(idx?: Index) {
    return await this.connectionStore.getCount(idx);
  }
}
