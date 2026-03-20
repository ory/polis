import {
  SetupLink,
  SetupLinkCreatePayload,
  Storable,
  PaginationParams,
  SetupLinkService,
  Index,
  JacksonOption,
} from '../typings';
import * as dbutils from '../db/utils';
import { IndexNames, validateTenantAndProduct, validateRedirectUrl, extractRedirectUrls } from './utils';
import crypto from 'crypto';
import { JacksonError } from './error';

interface FilterByParams extends PaginationParams {
  service?: SetupLinkService;
  tenant?: string;
  product?: string;
}

export type RemoveSetupLinkParams =
  | {
      id: string;
    }
  | {
      service: SetupLinkService;
      tenant: string;
      product: string;
    };

const throwIfInvalidService = (service: string) => {
  if (!['sso', 'dsync'].includes(service)) {
    throw new JacksonError('Invalid service provided. Supported values are: sso, dsync', 400);
  }
};

const calculateExpiryTimestamp = (expiryDays: number): number => {
  const currentTimestamp = Date.now();
  return currentTimestamp + expiryDays * 24 * 60 * 60 * 1000;
};

export class SetupLinkController {
  setupLinkStore: Storable;
  opts: JacksonOption;

  constructor({ setupLinkStore, opts }) {
    this.setupLinkStore = setupLinkStore;
    this.opts = opts;
  }

  /**
   * @openapi
   * components:
   *   schemas:
   *     SetupLink:
   *       type: object
   *       properties:
   *         setupID:
   *           type: string
   *           description: Setup link ID
   *         tenant:
   *           type: string
   *           description: Tenant
   *         product:
   *           type: string
   *           description: Product
   *         validTill:
   *           type: string
   *           description: Valid till timestamp
   *         url:
   *           type: string
   *           description: Setup link URL
   *       example:
   *         data:
   *           setupID: 0689f76f7b5aa22f00381a124cb4b153fc1a8c08
   *           tenant: acme
   *           product: my-app
   *           service: sso
   *           validTill: 1689849146690
   *           url: http://localhost:5225/setup/0b96a483ebfe0af0b561dda35a96647074d944631ff9e070
   *   parameters:
   *     setupLinkId:
   *       name: id
   *       in: query
   *       description: Setup link ID
   *       schema:
   *         type: string
   *     idParamGet:
   *       name: id
   *       in: query
   *       description: Setup Link ID
   *       schema:
   *         type: string
   *
   */

  /**
   * @openapi
   * /api/v1/sso/setuplinks:
   *   post:
   *     tags:
   *       - Setup Links | Single Sign On
   *     summary: Create a Setup Link
   *     operationId: create-sso-setup-link
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
   *               tenant:
   *                 type: string
   *                 description: Tenant
   *               product:
   *                 type: string
   *                 description: Product
   *               defaultRedirectUrl:
   *                 type: string
   *                 description: The redirect URL to use in the IdP login flow
   *               redirectUrl:
   *                 type: string
   *                 description: JSON encoded array containing a list of allowed redirect URLs
   *               expiryDays:
   *                 type: number
   *                 description: Days in number for the setup link to expire
   *                 default: 3
   *               regenerate:
   *                 type: boolean
   *                 description: If passed as true, it will remove the existing setup link and create a new one.
   *                 default: false
   *       required: true
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/SetupLink"
   * /api/v1/dsync/setuplinks:
   *   post:
   *     tags:
   *       - Setup Links | Directory Sync
   *     summary: Create a Setup Link
   *     operationId: create-dsync-setup-link
   *     requestBody:
   *       content:
   *         application/json:
   *           schema:
   *             required:
   *               - product
   *               - tenant
   *               - webhook_secret
   *               - webhook_url
   *             type: object
   *             properties:
   *               name:
   *                 type: string
   *                 description: Name of connection
   *               tenant:
   *                 type: string
   *                 description: Tenant
   *               product:
   *                 type: string
   *                 description: Product
   *               webhook_url:
   *                 type: string
   *                 description: The URL to send the directory sync events to
   *               webhook_secret:
   *                 type: string
   *                 description: The secret to sign the directory sync events
   *               expiryDays:
   *                 type: number
   *                 description: Days in number for the setup link to expire
   *                 default: 3
   *               regenerate:
   *                 type: boolean
   *                 description: If passed as true, it will remove the existing setup link and create a new one.
   *                 default: false
   *       required: true
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/SetupLink"
   *     x-ory-ratelimit-bucket: polis-public-medium
   */
  async create(body: SetupLinkCreatePayload): Promise<SetupLink> {
    const { name, tenant, product, service, expiryDays, regenerate } = body;

    validateTenantAndProduct(tenant, product);
    throwIfInvalidService(service);

    if (!tenant || !product) {
      throw new JacksonError('Must provide tenant and product', 400);
    }

    if (service === 'sso') {
      const { defaultRedirectUrl, redirectUrl } = body;

      if (!defaultRedirectUrl || !redirectUrl) {
        throw new JacksonError('Must provide defaultRedirectUrl and redirectUrl', 400);
      }

      validateRedirectUrl({ defaultRedirectUrl, redirectUrlList: extractRedirectUrls(redirectUrl || '') });
    } else if (service === 'dsync') {
      const { webhook_url, webhook_secret } = body;

      if (!webhook_url || !webhook_secret) {
        throw new JacksonError('Must provide webhook_url and webhook_secret', 400);
      }
    }

    const existing: SetupLink[] = (
      await this.setupLinkStore.getByIndex({
        name: IndexNames.TenantProductService,
        value: dbutils.keyFromParts(tenant, product, service),
      })
    ).data;

    if (existing.length > 0 && !regenerate && !this.isExpired(existing[0])) {
      return existing[0];
    }

    // Remove the existing setup link if regenerate is true
    if (existing.length > 0 && regenerate) {
      await this.setupLinkStore.delete(existing[0].setupID);
    }

    const token = crypto.randomBytes(24).toString('hex');
    const expiryInDays =
      typeof expiryDays === 'number' && expiryDays > 0 ? expiryDays : this.opts.setupLinkExpiryDays || 3;
    const setupID = dbutils.keyDigest(dbutils.keyFromParts(tenant, product, service));

    const setupLink: SetupLink = {
      setupID,
      tenant,
      product,
      service,
      name,
      validTill: calculateExpiryTimestamp(expiryInDays),
      url: `${this.opts.externalUrl}/setup/${token}`,
    };

    if (service === 'sso') {
      const { defaultRedirectUrl, redirectUrl, description } = body;
      setupLink.defaultRedirectUrl = defaultRedirectUrl;
      setupLink.redirectUrl = redirectUrl;
      setupLink.description = description || '';
    } else if (service === 'dsync') {
      const { webhook_url, webhook_secret } = body;
      setupLink.webhook_url = webhook_url;
      setupLink.webhook_secret = webhook_secret;
    }

    await this.setupLinkStore.put(
      setupID,
      setupLink,
      {
        name: IndexNames.SetupToken,
        value: token,
      },
      {
        name: IndexNames.TenantProductService,
        value: dbutils.keyFromParts(tenant, product, service),
      },
      {
        name: IndexNames.Service,
        value: service,
      },
      {
        name: IndexNames.ProductService,
        value: dbutils.keyFromParts(product, service),
      }
    );

    return setupLink;
  }

  // Get a setup link by token
  async getByToken(token: string): Promise<SetupLink> {
    if (!token) {
      throw new JacksonError('Missing setup link token', 400);
    }

    const setupLink: SetupLink[] = (
      await this.setupLinkStore.getByIndex({
        name: IndexNames.SetupToken,
        value: token,
      })
    ).data;

    if (!setupLink || setupLink.length === 0) {
      throw new JacksonError('Setup link is not found', 404);
    }

    if (this.isExpired(setupLink[0])) {
      throw new JacksonError('Setup link is expired', 401);
    }

    return setupLink[0];
  }

  /**
   * @openapi
   * /api/v1/sso/setuplinks:
   *   delete:
   *     tags:
   *       - Setup Links | Single Sign On
   *     summary: Delete the Setup Link
   *     operationId: delete-sso-setup-link
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
   *       - name: id
   *         in: query
   *         description: Setup link ID
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               example:
   *                 data: {}
   * /api/v1/dsync/setuplinks:
   *   delete:
   *     tags:
   *       - Setup Links | Directory Sync
   *     summary: Delete the Setup Link
   *     operationId: delete-dsync-setup-link
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
   *       - name: id
   *         in: query
   *         description: Setup link ID
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               example:
   *                 data: {}
   *     x-ory-ratelimit-bucket: polis-public-medium
   */
  async remove(params: RemoveSetupLinkParams) {
    if ('id' in params) {
      await this.setupLinkStore.delete(params.id);
      return;
    }

    if ('service' in params && 'tenant' in params && 'product' in params) {
      const { data: setupLinks } = await this.filterBy({
        service: params.service,
        tenant: params.tenant,
        product: params.product,
      });

      await this.remove({ id: setupLinks[0].setupID });
    }
  }

  // Check if a setup link is expired or not
  isExpired(setupLink: SetupLink): boolean {
    return setupLink.validTill < +new Date();
  }

  /**
   * @openapi
   * /api/v1/sso/setuplinks/product:
   *   get:
   *     tags:
   *       - Setup Links | Single Sign On
   *     summary: Get the Setup Links by product
   *     operationId: get-sso-setup-link-by-product
   *     parameters:
   *       - $ref: '#/components/parameters/productParamGet'
   *       - $ref: '#/components/parameters/pageOffset'
   *       - $ref: '#/components/parameters/pageLimit'
   *       - $ref: '#/components/parameters/pageToken'
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 $ref: "#/components/schemas/SetupLink"
   * /api/v1/dsync/setuplinks/product:
   *   get:
   *     tags:
   *       - Setup Links | Directory Sync
   *     summary: Get the Setup Links by product
   *     operationId: get-dsync-setup-link-by-product
   *     parameters:
   *       - $ref: '#/components/parameters/productParamGet'
   *       - $ref: '#/components/parameters/pageOffset'
   *       - $ref: '#/components/parameters/pageLimit'
   *       - $ref: '#/components/parameters/pageToken'
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 $ref: "#/components/schemas/SetupLink"
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  async filterBy(params: FilterByParams): Promise<{ data: SetupLink[]; pageToken?: string }> {
    const { tenant, product, service, pageOffset, pageLimit, pageToken } = params;

    let index: Index | null = null;

    // By tenant + product + service
    if (tenant && product && service) {
      index = {
        name: IndexNames.TenantProductService,
        value: dbutils.keyFromParts(tenant, product, service),
      };
    }

    // By product + service
    else if (product && service) {
      index = {
        name: IndexNames.ProductService,
        value: dbutils.keyFromParts(product, service),
      };
    }

    // By service
    else if (service) {
      index = {
        name: IndexNames.Service,
        value: service,
      };
    }

    if (!index) {
      throw new JacksonError('Please provide either service or product to filter setup links', 400);
    }

    const { data: setupLinks, pageToken: nextPageToken } = await this.setupLinkStore.getByIndex(
      index,
      pageOffset,
      pageLimit,
      pageToken
    );

    if (index.name === IndexNames.TenantProductService && setupLinks.length === 0) {
      throw new JacksonError('Setup link is not found', 404);
    }

    return { data: setupLinks, pageToken: nextPageToken };
  }

  /**
   * @openapi
   * /api/v1/sso/setuplinks:
   *   get:
   *     tags:
   *       - Setup Links | Single Sign On
   *     summary: Get the Setup Link
   *     operationId: get-sso-setup-link
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
   *       - name: id
   *         in: query
   *         description: Setup Link ID
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/SetupLink"
   * /api/v1/dsync/setuplinks:
   *   get:
   *     tags:
   *       - Setup Links | Directory Sync
   *     summary: Get the Setup Link
   *     operationId: get-dsync-setup-link
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
   *       - name: id
   *         in: query
   *         description: Setup Link ID
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/SetupLink"
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  async get(id: string): Promise<SetupLink> {
    if (!id) {
      throw new JacksonError('Missing setup link id', 400);
    }

    const setupLink = await this.setupLinkStore.get(id);

    if (!setupLink) {
      throw new JacksonError('Setup link is not found', 404);
    }

    return setupLink;
  }
}
