import _ from 'lodash';
import { randomUUID } from 'crypto';

import type {
  Directory,
  DirectorySyncEvent,
  IDirectoryConfig,
  Storable,
  CronLock,
  IWebhookEventsLogger,
  JacksonOptionWithRequiredLogger,
} from '../../typings';
import { sendPayloadToWebhook } from '../../event/webhook';
import { isConnectionActive } from '../../controller/utils';
import { JacksonError } from '../../controller/error';
import * as metrics from '../../opentelemetry/metrics';
import { indexNames } from '../scim/utils';

enum EventStatus {
  PENDING = 'PENDING',
  FAILED = 'FAILED',
  PROCESSING = 'PROCESSING',
}

interface QueuedEvent {
  event: DirectorySyncEvent;
  id: string;
  retry_count: number;
  status: EventStatus;
  created_at: string;
}

interface DirectoryEventsParams {
  opts: JacksonOptionWithRequiredLogger;
  eventStore: Storable;
  eventLock: CronLock;
  directories: IDirectoryConfig;
  webhookLogs: IWebhookEventsLogger;
}

let isJobRunning = false;
let intervalId: NodeJS.Timeout;

export class EventProcessor {
  private eventStore: Storable;
  private eventLock: CronLock;
  private opts: JacksonOptionWithRequiredLogger;
  private directories: IDirectoryConfig;
  private webhookLogs: IWebhookEventsLogger;
  private cronInterval: number | undefined;

  constructor({ opts, eventStore, eventLock, directories, webhookLogs }: DirectoryEventsParams) {
    this.opts = opts;
    this.eventLock = eventLock;
    this.eventStore = eventStore;
    this.directories = directories;
    this.webhookLogs = webhookLogs;
    this.cronInterval = this.opts.dsync?.webhookBatchCronInterval;

    if (this.cronInterval) {
      this.scheduleWorker = this.scheduleWorker.bind(this);
      this.scheduleWorker();
    }
  }

  // Push the new event to the database
  public async push(event: DirectorySyncEvent): Promise<QueuedEvent> {
    const id = randomUUID();

    const record = {
      id,
      event,
      retry_count: 0,
      status: EventStatus.PENDING,
      created_at: new Date().toISOString(),
    };

    const index = [
      {
        name: indexNames.directoryId,
        value: event.directory_id,
      },
    ];

    await this.eventStore.put(id, record, ...index);

    return record;
  }

  private async _process() {
    const batchSize = this.opts.dsync?.webhookBatchSize || 50;

    while (true) {
      const events = await this.fetchNextBatch(0, batchSize);
      const eventsCount = events.length;

      if (eventsCount === 0) {
        await this.eventLock.release();
        break;
      }

      // Group the events by directory
      const eventsByDirectory = _.groupBy(events, 'event.directory_id');
      const directoryIds = Object.keys(eventsByDirectory);
      const directoryCount = directoryIds.length;

      // Fetch the connections corresponding to the directories it belongs to
      const directoriesResult = await Promise.allSettled(
        directoryIds.map((directoryId) => this.directories.get(directoryId))
      );

      // Iterate over the directories and send the events to the webhooks
      // For each directory, we will send the events in a batch
      // directoryIds and directoriesResult are in the same order
      for (let i = 0; i < directoryCount; i++) {
        const directoryId = directoryIds[i];
        const directoryResult = directoriesResult[i];
        const events = eventsByDirectory[directoryId];

        if (directoryResult.status === 'rejected') {
          await this.markAsFailed(events);
          continue;
        }

        const directory = directoryResult.value.data as Directory;

        if (!directory) {
          this.opts.logger.error(`Directory ${directoryId} not found. Deleting the dsync events.`);
          await this.delete(events);
          continue;
        }

        if (!isConnectionActive(directory)) {
          this.opts.logger.error(`Directory ${directoryId} is not active. Deleting the dsync events.`);
          await this.delete(events);
          continue;
        }

        if (!directory.webhook.endpoint || !directory.webhook.secret) {
          this.opts.logger.error(
            `Webhook not configured for directory ${directoryId}. Deleting the dsync events.`
          );
          await this.delete(events);
          continue;
        }

        try {
          const { status } = await this.send(directory.webhook, events);

          if (status === 200) {
            await this.delete(events);
          } else {
            this.opts.logger.error(`Webhook returned status ${status}. Marking the events as failed.`);
            await this.markAsFailed(events);
          }

          await this.logWebhookEvent(directory, events, status);
        } catch (err: any) {
          const message = `Error sending payload to webhook ${directory.webhook.endpoint}. Marking the events as failed. ${err.message}`;
          const status = err.response?.status || 500;

          this.opts.logger.error(message, err);

          await this.markAsFailed(events);
          await this.logWebhookEvent(directory, events, status);

          throw new JacksonError(message, status);
        }
      }
    }
  }

  // Process the events and send them to the webhooks as a batch
  public async process() {
    if (isJobRunning) {
      this.opts.logger.info('A batch process is already running, skipping.');
      return;
    }

    if (!(await this.eventLock.acquire())) {
      return;
    }

    isJobRunning = true;

    try {
      this._process();
    } catch (e: any) {
      this.opts.logger.error(' Error processing webhooks batch:', e);
    }

    isJobRunning = false;

    if (this.cronInterval) {
      this.scheduleWorker();
    }
  }

  // Fetch next batch of events from the database
  public async fetchNextBatch(offset: number, limit: number) {
    const { data: events } = (await this.eventStore.getAll(offset, limit, undefined, 'ASC')) as {
      data: QueuedEvent[];
    };

    if (!events.length) {
      return [];
    }

    // Check if all the events in the batch have failed
    if (events.every((event) => event.status === EventStatus.FAILED)) {
      await this.notifyAllEventsFailed();
    }

    // Update the status of the events to PROCESSING
    const promises = events.map((event) =>
      this.eventStore.put(event.id, { ...event, status: EventStatus.PROCESSING })
    );

    await Promise.allSettled(promises);

    return events;
  }

  // Send the events to the webhooks
  private async send(webhook: Directory['webhook'], events: QueuedEvent[]) {
    const payload = events.map(({ event }) => event);

    try {
      return await sendPayloadToWebhook(webhook, payload, this.opts?.dsync?.debugWebhooks, this.opts.logger);
    } catch (err: any) {
      this.opts.logger.error(`Error sending payload to webhook: ${err.message}`);
      throw err;
    }
  }

  // Delete the delivered events
  private async delete(events: QueuedEvent[]) {
    const promises = events.map((event) => this.eventStore.delete(event.id));
    await Promise.allSettled(promises);
  }

  // Mark the events as failed
  private async markAsFailed(events: QueuedEvent[]) {
    const promises = events.map((event) =>
      this.eventStore.put(event.id, {
        ...event,
        status: EventStatus.FAILED,
        retry_count: event.retry_count + 1,
      })
    );

    await Promise.allSettled(promises);
  }

  private async logWebhookEvent(directory: Directory, events: QueuedEvent[], status: number) {
    if (!directory.log_webhook_events) {
      return;
    }

    const payload = events.map(({ event }) => event);

    await this.webhookLogs
      .setTenantAndProduct(directory.tenant, directory.product)
      .log(directory, payload, status);
  }

  // Send a OpenTelemetry event indicating that all the events in the batch have failed
  private async notifyAllEventsFailed() {
    metrics.increment('dsyncEventsBatchFailed');
    this.opts.logger.error('All events in the batch have failed. Please check the system.');
  }

  public async scheduleWorker() {
    if (!this.cronInterval) {
      return;
    }

    if (intervalId) {
      clearInterval(intervalId);
    }

    intervalId = setInterval(() => this.process(), this.cronInterval * 1000);
  }
}
