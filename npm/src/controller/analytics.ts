import {
  IConnectionAPIController,
  IDirectorySyncController,
  JacksonOptionWithRequiredLogger,
  Storable,
} from '../typings';
import Mixpanel from 'mixpanel';
import { randomUUID } from 'crypto';

type Event = {
  event: string;
  properties: Record<string, unknown>;
};

const idKey = 'heartbeat';
const sentKey = 'lastSent';

export class AnalyticsController {
  analyticsStore: Storable;
  connectionAPIController: IConnectionAPIController;
  directorySyncController: IDirectorySyncController;
  client: ReturnType<typeof Mixpanel.init>;
  anonymousId: string;
  private opts: JacksonOptionWithRequiredLogger;

  constructor({ opts, analyticsStore, connectionAPIController, directorySyncController }) {
    this.analyticsStore = analyticsStore;
    this.client = Mixpanel.init('1028494897a5520b90e7344344060fa7', {
      host: 'api-eu.mixpanel.com',
    });
    this.connectionAPIController = connectionAPIController;
    this.directorySyncController = directorySyncController;
    this.anonymousId = '';
    this.opts = opts;
  }

  public async init(): Promise<void> {
    this.anonymousId = await this.analyticsStore.get(idKey);
    if (!this.anonymousId || this.anonymousId === '') {
      this.anonymousId = randomUUID();
      this.analyticsStore.put(idKey, this.anonymousId);
    }

    const sent = await this.analyticsStore.get(sentKey);
    const msBetweenDates = Math.abs(new Date().getTime() - new Date(sent || 0).getTime());
    const hoursBetweenDates = msBetweenDates / (60 * 60 * 1000);

    if (hoursBetweenDates >= 24) {
      await this.send();
    }

    setInterval(
      async () => {
        await this.send();
      },
      60 * 60 * 24 * 1000
    );
  }

  async send() {
    try {
      const sso_connections_count = await this.connectionAPIController.getCount();
      const dsync_connections_count = await this.directorySyncController.directories.getCount();
      const events: Event[] = [
        {
          event: idKey,
          properties: {
            distinct_id: this.anonymousId,
          },
        },
      ];
      if (sso_connections_count || dsync_connections_count) {
        events.push({
          event: 'usage',
          properties: {
            distinct_id: this.anonymousId,
            'SSO Connections': sso_connections_count,
            'Directory Sync Connections': dsync_connections_count,
          },
        });
      }

      this.client.track_batch(events, (err: Error[] | undefined) => {
        if (err?.length) {
          setTimeout(
            () => {
              this.send();
            },
            1000 * 60 * 60
          );
          return;
        }

        this.analyticsStore.put(sentKey, new Date().toISOString());
      });
    } catch (err) {
      this.opts.logger.error('Error sending analytics', err);
    }
  }
}
