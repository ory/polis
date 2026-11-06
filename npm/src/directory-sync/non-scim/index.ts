import { newGoogleProvider } from './google';
import type {
  IDirectoryConfig,
  IUsers,
  IGroups,
  IRequestHandler,
  EventCallback,
  CronLock,
  JacksonOptionWithRequiredLogger,
} from '../../typings';
import { SyncUsers } from './syncUsers';
import { SyncGroups } from './syncGroups';
import { SyncGroupMembers } from './syncGroupMembers';

interface SyncParams {
  userController: IUsers;
  groupController: IGroups;
  opts: JacksonOptionWithRequiredLogger;
  directories: IDirectoryConfig;
  requestHandler: IRequestHandler;
  eventCallback: EventCallback;
  eventLock: CronLock;
}

let isJobRunning = false;
let intervalId: NodeJS.Timeout;

export class SyncProviders {
  private userController: IUsers;
  private groupController: IGroups;
  private directories: IDirectoryConfig;
  private requestHandler: IRequestHandler;
  private opts: JacksonOptionWithRequiredLogger;
  private cronInterval: number | undefined;
  private eventCallback: EventCallback;
  private eventLock: CronLock;

  constructor({
    userController,
    groupController,
    opts,
    directories,
    requestHandler,
    eventCallback,
    eventLock,
  }: SyncParams) {
    this.userController = userController;
    this.groupController = groupController;
    this.directories = directories;
    this.requestHandler = requestHandler;
    this.eventCallback = eventCallback;
    this.opts = opts;
    this.cronInterval = this.opts.dsync?.providers?.google.cronInterval;
    this.eventLock = eventLock;

    if (this.cronInterval) {
      this.scheduleSync = this.scheduleSync.bind(this);
      this.scheduleSync();
    }
  }

  // Start the sync process
  public async startSync() {
    if (isJobRunning) {
      this.opts.logger.info('A sync process is already running, skipping.');
      return;
    }

    if (!(await this.eventLock.acquire())) {
      return;
    }

    isJobRunning = true;

    const { directory: provider } = newGoogleProvider({ directories: this.directories, opts: this.opts });

    const startTime = Date.now();

    try {
      const allDirectories = await provider.getDirectories();

      this.opts.logger.info(`Starting the sync process for ${allDirectories.length} directories`);

      for (const directory of allDirectories) {
        const params = {
          directory,
          provider,
          userController: this.userController,
          groupController: this.groupController,
          requestHandler: this.requestHandler,
          callback: this.eventCallback,
        };

        await new SyncUsers(params).sync();
        await new SyncGroups(params).sync();
        await new SyncGroupMembers(params).sync();
      }
    } catch (e: any) {
      this.opts.logger.error(' Error processing Google sync:', e);
    }

    await this.eventLock.release();

    const endTime = Date.now();
    this.opts.logger.info(`Sync process completed in ${(endTime - startTime) / 1000} seconds`);

    isJobRunning = false;

    if (this.cronInterval) {
      this.scheduleSync();
    }
  }

  // Schedule the next sync process
  private scheduleSync() {
    if (!this.cronInterval) {
      return;
    }

    if (intervalId) {
      clearInterval(intervalId);
    }

    intervalId = setInterval(() => this.startSync(), this.cronInterval * 1000);
  }
}
