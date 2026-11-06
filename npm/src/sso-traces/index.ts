import { GetByProductParams, Records, Storable, JacksonOptionWithRequiredLogger } from '../typings';
import { generateMnemonic } from '@boxyhq/error-code-mnemonic';
import { IndexNames } from '../controller/utils';
import { keyFromParts } from '../db/utils';
import type { SSOTrace, Trace } from './types';
import { JacksonError } from '../controller/error';

const INTERVAL_1_WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const INTERVAL_1_DAY_MS = 24 * 60 * 60 * 1000;
const SSO_TRACES_REDACT_KEYS = ['profile', 'oidcTokenSet', 'samlResponse'];

class SSOTraces {
  tracesStore: Storable;
  opts: JacksonOptionWithRequiredLogger;

  constructor({ tracesStore, opts }) {
    this.tracesStore = tracesStore;
    this.opts = opts;
    // Clean up stale traces at the start
    this.cleanUpStaleTraces();
    // Set timer to run every day
    setInterval(async () => {
      this.cleanUpStaleTraces();
    }, INTERVAL_1_DAY_MS);
  }

  public async saveTrace(payload: SSOTrace) {
    if (this.opts.ssoTraces?.disable) {
      return;
    }

    try {
      const { context } = payload;

      if (this.opts.ssoTraces?.redact) {
        SSO_TRACES_REDACT_KEYS.forEach((key) => delete context[key]);
      }
      // Friendly trace id
      const traceId: string = await generateMnemonic();
      // If timestamp present in payload use that value, else generate the current timestamp
      const timestamp = typeof payload.timestamp === 'number' ? payload.timestamp : Date.now();
      const traceValue: Trace = { ...payload, traceId, timestamp };
      const { tenant, product, clientID } = context;

      const indices = [
        {
          name: IndexNames.TenantProduct,
          value: keyFromParts(tenant, product),
          filterLogic: ({ tenant, product }) => !!(tenant && product),
        },
        {
          name: IndexNames.SSOClientID,
          value: clientID,
          filterLogic: ({ clientID }) => !!clientID,
        },
        {
          name: IndexNames.Product,
          value: product,
          filterLogic: ({ product }) => !!product,
        },
      ]
        .filter(({ filterLogic }) => filterLogic(context))
        .map(({ name, value }) => ({ name, value }));

      await this.tracesStore.put(traceId, traceValue, ...indices);
      return traceId;
    } catch (err: unknown) {
      this.opts.logger.error(`Failed to save trace`, err);
    }
  }

  /**
   * @openapi
   * components:
   *   schemas:
   *     SSOTrace:
   *       type: object
   *       properties:
   *         traceId:
   *           type: string
   *           description: Trace ID
   *         error:
   *           type: string
   *           description: Error
   *         timestamp:
   *           type: string
   *           description: Timestamp
   *         context:
   *           type: object
   *           properties:
   *             tenant:
   *               type: string
   *               description: Tenant
   *             product:
   *               type: string
   *               description: Product
   *             clientID:
   *               type: string
   *               description: Connection client ID
   *             issuer:
   *               type: string
   *               description: Issuer
   *             relayState:
   *               type: string
   *               description: Relay state
   *             samlResponse:
   *               type: string
   *               description: SAML response
   *             isSAMLFederated:
   *               type: boolean
   *               description: Indicates if SAML is federated
   *             isOIDCFederated:
   *               type: boolean
   *               description: Indicates if OIDC is federated
   *             isIdPFlow:
   *               type: boolean
   *               description: Indicates if request is from IdP
   *
   */

  /**
   * @openapi
   * /api/v1/sso-traces:
   *   get:
   *     tags:
   *       - SSO Traces
   *     summary: Get trace by ID
   *     parameters:
   *       - name: id
   *         in: query
   *         description: Trace ID
   *         required: true
   *         schema:
   *           type: string
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *             schema:
   *               $ref: "#/components/schemas/SSOTrace"
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  public async getByTraceId(traceId: string) {
    return (await this.tracesStore.get(traceId)) as Trace;
  }

  public async getAllTraces(
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string
  ): Promise<Records<Trace>> {
    return await this.tracesStore.getAll(pageOffset || 0, pageLimit || 0, pageToken);
  }

  /** Cleans up stale traces older than 1 week */
  public async cleanUpStaleTraces() {
    let staleTraces: Trace[] = [];
    for (let pageOffset = 0, pageTokenMap = {}; ; pageOffset += 50) {
      const { data: page, pageToken: nextPageToken } = await this.getAllTraces(
        pageOffset,
        50,
        pageTokenMap[pageOffset]
      );
      pageTokenMap[pageOffset + 50] = nextPageToken;
      if (page.length === 0) {
        break;
      }
      staleTraces = staleTraces.concat(
        page.filter(({ timestamp }) => Date.now() - timestamp > INTERVAL_1_WEEK_MS)
      );
    }

    for (let i = 0; i < staleTraces.length; i++) {
      await this.tracesStore.delete(staleTraces[i].traceId);
    }
  }

  /**
   * @openapi
   * /api/v1/sso-traces/product:
   *   get:
   *     tags:
   *       - SSO Traces
   *     summary: Get all traces for a product
   *     parameters:
   *      - $ref: '#/components/parameters/product'
   *      - $ref: '#/components/parameters/pageOffset'
   *      - $ref: '#/components/parameters/pageLimit'
   *      - $ref: '#/components/parameters/pageToken'
   *     responses:
   *       '200':
   *         description: Success
   *         content:
   *           application/json:
   *              schema:
   *                type: object
   *                properties:
   *                  data:
   *                    type: array
   *                    items:
   *                      $ref: '#/components/schemas/SSOTrace'
   *                  pageToken:
   *                    type: string
   *                    description: token for pagination
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  public async getTracesByProduct(params: GetByProductParams) {
    const { product, pageOffset, pageLimit, pageToken } = params;

    if (!product) {
      throw new JacksonError('Please provide a `product`.', 400);
    }

    const traces = await this.tracesStore.getByIndex(
      {
        name: IndexNames.Product,
        value: product,
      },
      pageOffset,
      pageLimit,
      pageToken
    );

    return traces;
  }

  public async deleteTracesByProduct(product: string) {
    let pageToken;
    do {
      const res = await this.getTracesByProduct({
        product,
        pageOffset: 0,
        pageLimit: 50,
      });
      if (!res.data || !res.data.length) {
        break;
      }
      pageToken = res.pageToken;
      // deleting traces in batches of 50
      // deleting in the loop right away as we get the traces
      await this.tracesStore.deleteMany((res.data || []).map((t) => t.traceId));
    } while (pageToken);
  }

  public async countByProduct(product: string) {
    return await this.tracesStore.getCount({
      name: IndexNames.Product,
      value: product,
    });
  }
}

export default SSOTraces;
