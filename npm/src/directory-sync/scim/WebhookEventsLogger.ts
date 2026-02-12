import { randomUUID } from 'crypto';

import type {
  Directory,
  DatabaseStore,
  WebhookEventLog,
  DirectorySyncEvent,
  PaginationParams,
  Records,
} from '../../typings';
import { Base } from './Base';
import { webhookLogsTTL } from '../utils';
import { indexNames } from './utils';

type GetAllParams = PaginationParams & {
  directoryId?: string;
};

export class WebhookEventsLogger extends Base {
  constructor({ db }: { db: DatabaseStore }) {
    super({ db });
  }

  public async log(directory: Directory, event: DirectorySyncEvent | DirectorySyncEvent[], status: number) {
    const id = randomUUID();

    const log: WebhookEventLog = {
      id,
      payload: event,
      webhook_endpoint: directory.webhook.endpoint,
      created_at: new Date(),
      status_code: status,
      delivered: status === 200,
    };

    await this.eventStore().put(id, log, {
      name: indexNames.directoryId,
      value: directory.id,
    });

    return log;
  }

  public async get(id: string): Promise<WebhookEventLog> {
    return await this.eventStore().get(id);
  }

  /**
   * @openapi
   * components:
   *   schemas:
   *     Event:
   *       type: object
   *       example:
   *         id: id1
   *         webhook_endpoint: https://example.com/webhook
   *         created_at: "2024-03-05T17:06:26.074Z"
   *         status_code: 200
   *         delivered: true
   *         payload:
   *           directory_id: 58b5cd9dfaa39d47eb8f5f88631f9a629a232016
   *           event: user.created
   *           tenant: boxyhq
   *           product: jackson
   *           data:
   *             id: 038e767b-9bc6-4dbd-975e-fbc38a8e7d82
   *             first_name: Deepak
   *             last_name: Prabhakara
   *             email: deepak@example.com
   *             active: true
   *             raw:
   *               schemas:
   *                 - urn:ietf:params:scim:schemas:core:2.0:User
   *               userName: deepak@example.com
   *               name:
   *                 givenName: Deepak
   *                 familyName: Prabhakara
   *               emails:
   *                 - primary: true
   *                   value: deepak@example.com
   *                   type: work
   *               title: CEO
   *               displayName: Deepak Prabhakara
   *               locale: en-US
   *               externalId: 00u1ldzzogFkXFmvT5d7
   *               groups: []
   *               active: true
   *
   */

  /**
   * @openapi
   * /api/v1/dsync/events:
   *   get:
   *     tags:
   *       - Directory Sync
   *     summary: Get event logs for a directory
   *     parameters:
   *       - $ref: '#/components/parameters/directoryId'
   *       - $ref: '#/components/parameters/tenant'
   *       - $ref: '#/components/parameters/product'
   *       - $ref: '#/components/parameters/pageOffset'
   *       - $ref: '#/components/parameters/pageLimit'
   *       - $ref: '#/components/parameters/pageToken'
   *     responses:
   *       200:
   *         description: Success
   *         content:
   *           application/json:
   *              schema:
   *                type: object
   *                properties:
   *                  data:
   *                    type: array
   *                    items:
   *                      $ref: '#/components/schemas/Event'
   *                  pageToken:
   *                    type: string
   *                    description: token for pagination
   *     x-ory-ratelimit-bucket: polis-public-low
   */
  // Get the event logs for a directory paginated
  public async getAll(params: GetAllParams = {}) {
    const { pageOffset, pageLimit, pageToken, directoryId } = params;

    let result: Records<WebhookEventLog>;

    if (directoryId) {
      const index = {
        name: indexNames.directoryId,
        value: directoryId,
      };

      result = await this.eventStore().getByIndex(index, pageOffset, pageLimit, pageToken);
    } else {
      result = await this.eventStore().getAll(pageOffset, pageLimit, pageToken);
    }

    return { data: result.data, pageToken: result.pageToken };
  }

  public async delete(id: string) {
    await this.eventStore().delete(id);
  }

  // Delete all event logs for a directory
  async deleteAll(directoryId: string) {
    while (true) {
      const { data: events } = await this.eventStore().getByIndex(
        {
          name: indexNames.directoryId,
          value: directoryId,
        },
        0,
        this.bulkDeleteBatchSize
      );

      if (!events || events.length === 0) {
        break;
      }

      await this.eventStore().deleteMany(events.map((event) => event.id));
    }
  }

  // Get the store for the events
  private eventStore() {
    return this.store('logs', webhookLogsTTL);
  }
}
