import type {
  DirectorySyncEventType,
  Directory,
  User,
  Group,
  EventCallback,
  DirectorySyncEvent,
  IWebhookEventsLogger,
  IDirectoryConfig,
  IEventProcessor,
  JacksonOptionWithRequiredLogger,
} from '../typings';
import { sendPayloadToWebhook } from '../event/webhook';
import { transformEventPayload } from './scim/transform';
import { JacksonError } from '../controller/error';

export const eventLockTTL = 30;
export const webhookLogsTTL = 7 * 24 * 60 * 60;
export const eventLockKey = 'dsync-event-lock';
export const googleLockKey = 'dsync-google-lock';

interface Payload {
  directory: Directory;
  group?: Group | null;
  user?: User | null;
}

interface EventCallbackParams {
  opts: JacksonOptionWithRequiredLogger;
  directories: IDirectoryConfig;
  eventProcessor: IEventProcessor;
  webhookLogs: IWebhookEventsLogger;
}

export const sendEvent = async (
  event: DirectorySyncEventType,
  payload: Payload,
  callback?: EventCallback
) => {
  if (!callback) {
    return;
  }

  await callback(transformEventPayload(event, payload));
};

export const handleEventCallback = async ({
  opts,
  directories,
  eventProcessor,
  webhookLogs,
}: EventCallbackParams) => {
  // Callback that handles the events for Jackson service
  return async (event: DirectorySyncEvent) => {
    const { tenant, product, directory_id: directoryId } = event;

    const { data: directory, error } = await directories.get(directoryId);

    if (error) {
      opts.logger.error(`Error fetching directory ${directoryId}: ${error.message}`);
      throw new JacksonError(error.message, error.code);
    }

    if (!directory.webhook.endpoint || !directory.webhook.secret) {
      opts.logger.error(`Webhook not configured for directory ${directoryId}. Skipping ...`);
      return;
    }

    // If batch size is set, store the events in the database
    // We will process the queue later in the background
    if (opts.dsync?.webhookBatchSize) {
      await eventProcessor.push(event);
      return;
    }

    let status = 200;

    try {
      // Send the event to the webhook (synchronously)
      await sendPayloadToWebhook(directory.webhook, event, opts.dsync?.debugWebhooks, opts.logger);
    } catch (err: any) {
      status = err.response ? err.response.status : 500;
    }

    if (directory.log_webhook_events) {
      await webhookLogs.setTenantAndProduct(tenant, product).log(directory, event, status);
    }
  };
};
