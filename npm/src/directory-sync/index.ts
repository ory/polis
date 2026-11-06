import type { IEventController, DB, JacksonOptionWithRequiredLogger } from '../typings';
import { DirectoryConfig } from './scim/DirectoryConfig';
import { DirectoryUsers } from './scim/DirectoryUsers';
import { DirectoryGroups } from './scim/DirectoryGroups';
import { Users } from './scim/Users';
import { Groups } from './scim/Groups';
import { getDirectorySyncProviders } from './scim/utils';
import { RequestHandler } from './request';
import { WebhookEventsLogger } from './scim/WebhookEventsLogger';
import { newGoogleProvider } from './non-scim/google';
import { SyncProviders } from './non-scim';
import { storeNamespacePrefix } from '../controller/utils';
import { eventLockKey, eventLockTTL, googleLockKey, handleEventCallback } from './utils';
import { EventProcessor } from './batch-events/queue';
import { CronLock } from '../cron/lock';

const directorySync = async (params: {
  db: DB;
  opts: JacksonOptionWithRequiredLogger;
  eventController: IEventController;
}) => {
  const { db, opts, eventController } = params;

  const users = new Users({ db });
  const groups = new Groups({ db });
  const webhookLogs = new WebhookEventsLogger({ db });
  const directories = new DirectoryConfig({
    db,
    opts,
    users,
    groups,
    logger: webhookLogs,
    eventController,
  });

  const directoryUsers = new DirectoryUsers({ directories, users });
  const directoryGroups = new DirectoryGroups({ directories, users, groups });

  // Fetch the supported providers
  const getProviders = () => {
    return getDirectorySyncProviders();
  };

  const googleProvider = newGoogleProvider({ directories, opts });

  // Batch send events
  const eventStore = db.store(storeNamespacePrefix.dsync.events);
  const lockStore = db.store(storeNamespacePrefix.dsync.lock, eventLockTTL);
  const eventLock = new CronLock({ key: eventLockKey, lockStore, opts });
  const googleLock = new CronLock({ key: googleLockKey, lockStore, opts });
  const eventProcessor = new EventProcessor({
    opts,
    eventStore,
    eventLock,
    directories,
    webhookLogs,
  });

  // Internal callback handles sending webhooks
  const internalCallback = await handleEventCallback({
    opts,
    directories,
    webhookLogs,
    eventProcessor,
  });

  // Use the provided callback (Embedded) or fallback to the internal callback (Hosted)
  const _callback = opts.dsync?.callback || internalCallback;

  // SCIM handler
  const requestHandler = new RequestHandler({
    directoryUsers,
    directoryGroups,
    eventCallback: _callback,
  });

  // Google sync handler
  const syncProviders = new SyncProviders({
    userController: users,
    groupController: groups,
    opts,
    directories,
    requestHandler,
    eventCallback: _callback,
    eventLock: googleLock,
  });

  return {
    users,
    groups,
    directories,
    webhookLogs,
    requests: requestHandler,
    providers: getProviders,
    events: {
      batch: eventProcessor,
    },
    google: googleProvider.oauth,
    sync: syncProviders.startSync.bind(syncProviders),
  };
};

export default directorySync;
