import crypto from 'crypto';
import saml from '@boxyhq/saml20';

import type {
  Storable,
  JacksonOption,
  IdentityFederationApp,
  Records,
  GetByProductParams,
  AppRequestParams,
  Index,
} from '../../typings';
import { fedAppID, clientIDFederatedPrefix, GENERIC_ERR_STRING } from '../../controller/utils';
import { JacksonError } from '../../controller/error';
import { getDefaultCertificate } from '../../saml/x509';
import { IndexNames, validateTenantAndProduct } from '../../controller/utils';
import { throwIfInvalidLicense } from '../common/checkLicense';

type NewAppParams = Pick<
  IdentityFederationApp,
  | 'name'
  | 'tenant'
  | 'product'
  | 'acsUrl'
  | 'entityId'
  | 'tenants'
  | 'mappings'
  | 'type'
  | 'redirectUrl'
  | 'samlAudienceOverride'
  | 'ttlInMinutes'
> & {
  logoUrl?: string;
  faviconUrl?: string;
  primaryColor?: string;
};

export class App {
  protected store: Storable;
  private opts: JacksonOption;

  constructor({ store, opts }: { store: Storable; opts: JacksonOption }) {
    this.store = store;
    this.opts = opts;
  }

  /**
   * @openapi
   * components:
   *   schemas:
   *     IdentityFederationAppCreate:
   *       type: object
   *       properties:
   *         tenant:
   *           type: string
   *           description: Tenant
   *         product:
   *           type: string
   *           description: Product
   *         name:
   *           type: string
   *           description: Name
   *         acsUrl:
   *           type: string
   *           description: ACS URL
   *         entityId:
   *           type: string
   *           description: Entity ID
   *         logoUrl:
   *           type: string
   *           description: Logo URL
   *         faviconUrl:
   *           type: string
   *           description: Favicon URL
   *         primaryColor:
   *           type: string
   *           description: Primary color
   *         tenants:
   *           type: array
   *           items:
   *             type: string
   *           description: Mapping of tenants whose connections will be grouped under this Identity Federation app
   *         mappings:
   *           type: array
   *           items:
   *             $ref: "#/components/schemas/AttributeMapping"
   *           description: Mapping of attributes from the IdP to SP
   *         type:
   *           type: array
   *           items:
   *             type: string
   *           description: If creating an OIDC app, this should be set to 'oidc' otherwise it defaults to 'saml'
   *         redirectUrl:
   *           type: array
   *           items:
   *             type: string
   *           description: If creating an OIDC app, provide the redirect URL
   *         samlAudienceOverride:
   *           type: string
   *           description: Override the SAML Audience on a per app basis
   *         ttlInMinutes:
   *           type: number
   *           description: Time-to-live in minutes for the SAML assertion, does not apply to OIDC flows
   *     IdentityFederationApp:
   *       allOf:
   *         - $ref: "#/components/schemas/IdentityFederationAppCreate"
   *         - type: object
   *           required:
   *             - id
   *           properties:
   *             id:
   *               type: string
   *               description: App ID
   *     AttributeMapping:
   *       type: object
   *       properties:
   *         key:
   *           type: string
   *           description: SP attribute
   *         value:
   *           type: string
   *           description: IdP attribute
   *     IdentityFederationResponse:
   *       type: object
   *       properties:
   *         data:
   *           $ref: "#/components/schemas/IdentityFederationApp"
   *         error:
   *           $ref: "#/components/schemas/IdentityFederationError"
   *     IdentityFederationError:
   *       type: object
   *       properties:
   *         message:
   *           type: string
   *
   */

  /**
   * @openapi
   * /api/v1/identity-federation:
   *   post:
   *     tags:
   *       - Identity Federation
   *     summary: Create an Identity Federation app
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             $ref: "#/components/schemas/IdentityFederationAppCreate"
   *             required:
   *               - name
   *               - product
   *               - tenant
   *       required: true
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/IdentityFederationResponse"
   */
  public async create({
    name,
    type,
    redirectUrl,
    tenant,
    product,
    acsUrl,
    entityId,
    logoUrl,
    faviconUrl,
    primaryColor,
    tenants,
    mappings,
    samlAudienceOverride,
    ttlInMinutes,
  }: NewAppParams) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    if (type === 'oidc') {
      if (!tenant || !product || !redirectUrl || !name) {
        throw new JacksonError(
          'Missing required parameters. Required parameters are: name, tenant, product, redirectUrl',
          400
        );
      }
    } else {
      if (!tenant || !product || !acsUrl || !entityId || !name) {
        throw new JacksonError(
          'Missing required parameters. Required parameters are: name, tenant, product, acsUrl, entityId',
          400
        );
      }
    }

    validateTenantAndProduct(tenant, product);

    const id = fedAppID(tenant, product, type);

    // Check if an app already exists for the same tenant and product
    const foundApp = await this.store.get(id);

    if (foundApp) {
      throw new JacksonError(
        'Cannot create another app for the same tenant and product. An app already exists.',
        400
      );
    }

    if (type === 'saml') {
      // Check if an app already exists with the same entityId
      const result = await this.store.getByIndex({
        name: IndexNames.EntityID,
        value: entityId,
      });

      const apps: IdentityFederationApp[] = result.data;

      if (apps && apps.length > 0) {
        throw new JacksonError(
          `An app already exists with the same Entity ID. Provide a unique Entity ID and try again.`,
          400
        );
      }
    }

    let _tenants: string[] = [];

    if (tenants && tenants.length > 0) {
      _tenants = tenants.filter((t) => t !== tenant);
      _tenants.unshift(tenant);
    } else {
      _tenants.push(tenant);
    }

    const app: IdentityFederationApp = {
      id,
      type,
      redirectUrl,
      name,
      tenant,
      product,
      acsUrl,
      entityId,
      logoUrl: logoUrl || null,
      faviconUrl: faviconUrl || null,
      primaryColor: primaryColor || null,
      tenants: _tenants,
      mappings: mappings || [],
      samlAudienceOverride: samlAudienceOverride || null,
      ttlInMinutes: ttlInMinutes ?? null,
    };

    if (type === 'oidc') {
      app.clientID = `${clientIDFederatedPrefix}${id}`;
      app.clientSecret = crypto.randomBytes(24).toString('hex');
    }

    const indexes = [
      {
        name: IndexNames.Product,
        value: product,
      },
    ];

    if (type !== 'oidc') {
      indexes.push({
        name: IndexNames.EntityID,
        value: entityId,
      });
    }

    await this.store.put(id, app, ...indexes);

    return app;
  }

  /**
   * @openapi
   * /api/v1/identity-federation:
   *   get:
   *     tags:
   *       - Identity Federation
   *     summary: Get an Identity Federation app
   *     parameters:
   *       - name: id
   *         in: query
   *         description: App ID
   *         required: true
   *         schema:
   *           type: string
   *       - name: tenant
   *         in: query
   *         description: Tenant
   *         schema:
   *           type: string
   *       - name: product
   *         in: query
   *         description: Product
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/IdentityFederationResponse"
   */
  public async get(params: AppRequestParams) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    if ('id' in params) {
      const app = await this.store.get(params.id);

      if (!app) {
        throw new JacksonError('Identity Federation app not found', 404);
      }

      return app as IdentityFederationApp;
    }

    if ('tenant' in params && 'product' in params) {
      const app = await this.store.get(fedAppID(params.tenant, params.product, params.type));

      if (!app) {
        throw new JacksonError('Identity Federation app not found', 404);
      }

      return app as IdentityFederationApp;
    }

    throw new JacksonError('Provide either the `id` or `tenant` and `product` to get the app', 400);
  }

  /**
   * @openapi
   * /api/v1/identity-federation/product:
   *   get:
   *     tags:
   *       - Identity Federation
   *     summary: Get Identity Federation apps by product
   *     parameters:
   *       - name: product
   *         in: query
   *         description: Product
   *         required: true
   *         schema:
   *           type: string
   *       - $ref: '#/components/parameters/pageOffset'
   *       - $ref: '#/components/parameters/pageLimit'
   *       - $ref: '#/components/parameters/pageToken'
   *     responses:
   *        200:
   *          description: Success
   *          content:
   *            application/json:
   *               schema:
   *                 type: object
   *                 properties:
   *                   data:
   *                     type: array
   *                     items:
   *                       $ref: '#/components/schemas/IdentityFederationApp'
   *                   error:
   *                     $ref: '#/components/schemas/IdentityFederationError'
   *                   pageToken:
   *                     type: string
   *                     description: token for pagination
   */
  public async getByProduct({ product, pageOffset, pageLimit, pageToken }: GetByProductParams) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    if (!product) {
      throw new JacksonError('Please provide a `product`.', 400);
    }

    const apps = await this.store.getByIndex(
      {
        name: IndexNames.Product,
        value: product,
      },
      pageOffset,
      pageLimit,
      pageToken
    );

    return apps;
  }

  // Get the app by SP EntityId
  public async getByEntityId(entityId: string) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    if (!entityId) {
      throw new JacksonError(
        GENERIC_ERR_STRING,
        400,
        'Missing required parameters. Required parameters are: entityId'
      );
    }

    const apps: IdentityFederationApp[] = (
      await this.store.getByIndex({
        name: IndexNames.EntityID,
        value: entityId,
      })
    ).data;

    if (!apps || apps.length === 0) {
      throw new JacksonError(GENERIC_ERR_STRING, 404, 'Identity Federation app not found');
    }

    return apps[0];
  }

  /**
   * @openapi
   * /api/v1/identity-federation:
   *   patch:
   *     tags:
   *       - Identity Federation
   *     summary: Update an Identity Federation app
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             $ref: "#/components/schemas/IdentityFederationApp"
   *             required:
   *               - id
   *       required: true
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/IdentityFederationResponse"
   */
  public async update(params: Partial<IdentityFederationApp>) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    const { id, tenant, product, type } = params;

    if (!id && (!tenant || !product)) {
      throw new JacksonError('Provide either the `id` or `tenant` and `product` to update the app', 400);
    }

    let app: null | IdentityFederationApp = null;

    if (id) {
      app = await this.get({ id });
    } else if (tenant && product) {
      app = await this.get({ tenant, product, type });
    }

    if (!app) {
      throw new JacksonError('Identity Federation app not found', 404);
    }

    const toUpdate: Partial<IdentityFederationApp> = {};

    // Support partial updates

    if ('name' in params) {
      toUpdate['name'] = params.name;
    }

    if ('redirectUrl' in params) {
      toUpdate['redirectUrl'] = params.redirectUrl;
    }

    if ('acsUrl' in params) {
      toUpdate['acsUrl'] = params.acsUrl;
    }

    if ('logoUrl' in params) {
      toUpdate['logoUrl'] = params.logoUrl || null;
    }

    if ('faviconUrl' in params) {
      toUpdate['faviconUrl'] = params.faviconUrl || null;
    }

    if ('primaryColor' in params) {
      toUpdate['primaryColor'] = params.primaryColor || null;
    }

    if ('tenants' in params) {
      let _tenants: string[] = [];

      if (params.tenants && params.tenants.length > 0) {
        _tenants = params.tenants.filter((t) => t !== app?.tenant);
        _tenants.unshift(app.tenant);
      } else {
        _tenants.push(app.tenant);
      }

      toUpdate['tenants'] = _tenants;
    }

    if ('mappings' in params) {
      toUpdate['mappings'] = params.mappings;
    }

    if ('samlAudienceOverride' in params) {
      toUpdate['samlAudienceOverride'] = params.samlAudienceOverride;
    }

    if ('ttlInMinutes' in params) {
      toUpdate['ttlInMinutes'] = params.ttlInMinutes ?? null;
    }

    if (Object.keys(toUpdate).length === 0) {
      throw new JacksonError(
        'Please provide at least one of the following parameters: acsUrl, name, logoUrl, faviconUrl, primaryColor',
        400
      );
    }

    const updatedApp = {
      ...app,
      ...toUpdate,
    };

    await this.store.put(app.id, updatedApp);

    return updatedApp;
  }

  // Get all apps
  public async getAll({
    pageOffset,
    pageLimit,
    pageToken,
  }: {
    pageOffset?: number;
    pageLimit?: number;
    pageToken?: string;
  }) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    const apps = (await this.store.getAll(
      pageOffset,
      pageLimit,
      pageToken
    )) as Records<IdentityFederationApp>;

    return apps;
  }

  /**
   * @openapi
   * /api/v1/identity-federation:
   *   delete:
   *     tags:
   *       - Identity Federation
   *     summary: Delete an Identity Federation app
   *     parameters:
   *       - name: id
   *         in: query
   *         description: App ID
   *         required: true
   *         schema:
   *           type: string
   *       - name: tenant
   *         in: query
   *         description: Tenant
   *         schema:
   *           type: string
   *       - name: product
   *         in: query
   *         description: Product
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   $ref: "#/components/schemas/IdentityFederationError"
   */

  public async delete(params: AppRequestParams): Promise<void> {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    if ('id' in params) {
      return await this.store.delete(params.id);
    }

    if ('tenant' in params && 'product' in params) {
      const id = fedAppID(params.tenant, params.product, params.type);
      return await this.store.delete(id);
    }

    throw new JacksonError('Provide either the `id` or `tenant` and `product` to delete the app', 400);
  }

  // Get the metadata for the app
  public async getMetadata(samlAudienceOverride?: string) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    const { publicKey } = await getDefaultCertificate();

    const ssoUrl = `${this.opts.externalUrl}/api/identity-federation/sso`;
    const entityId = samlAudienceOverride ? samlAudienceOverride : this.opts.samlAudience!;

    const xml = saml.createIdPMetadataXML({
      entityId,
      ssoUrl,
      x509cert: publicKey,
      wantAuthnRequestsSigned: false,
    });

    return {
      xml,
      entityId,
      ssoUrl,
      x509cert: publicKey,
    };
  }

  public async getCount(idx?: Index) {
    return await this.store.getCount(idx);
  }
}
