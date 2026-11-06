import { randomUUID } from 'crypto';
import type { JacksonOptionWithRequiredLogger, Storable } from '../typings';
import { eventLockTTL } from '../directory-sync/utils';

const lockRenewalInterval = (eventLockTTL / 2) * 1000;
const g = global as any;
if (!g._instanceKey) {
  g._instanceKey = randomUUID();
}
const instanceKey = g._instanceKey;

interface Lock {
  key: string;
  created_at: string;
}

interface LockParams {
  lockStore: Storable;
  key: string;
  opts: JacksonOptionWithRequiredLogger;
}

export class CronLock {
  private lockStore: Storable;
  private key: string;
  private intervalId: NodeJS.Timeout | undefined;
  private opts: JacksonOptionWithRequiredLogger;

  constructor({ key, lockStore, opts }: LockParams) {
    this.lockStore = lockStore;
    this.key = key;
    this.opts = opts;
  }

  public async acquire() {
    try {
      const lock = await this.get();

      if (lock && !this.isExpired(lock)) {
        return lock.key === instanceKey;
      }

      await this.add();

      // Renew the lock periodically
      if (!this.intervalId) {
        this.intervalId = setInterval(async () => {
          this.renew();
        }, lockRenewalInterval);
      }

      return true;
    } catch (e: any) {
      this.opts.logger.error(`Error acquiring lock for ${instanceKey}`, e);
      return false;
    }
  }

  private async renew() {
    try {
      const lock = await this.get();

      if (!lock) {
        return;
      }

      if (lock.key !== instanceKey) {
        return;
      }

      await this.add();
    } catch (e: any) {
      this.opts.logger.error(`Error renewing lock for ${instanceKey}`, e);
    }
  }

  private async add() {
    const record = {
      key: instanceKey,
      created_at: new Date().toISOString(),
    };

    await this.lockStore.put(this.key, record);
  }

  private async get() {
    return (await this.lockStore.get(this.key)) as Lock;
  }

  public async release() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }

    const lock = await this.get();

    if (!lock) {
      return;
    }

    if (lock.key !== instanceKey) {
      return;
    }

    await this.lockStore.delete(this.key);
  }

  private isExpired(lock: Lock) {
    const lockDate = new Date(lock.created_at);
    const currentDate = new Date();
    const diffSeconds = (currentDate.getTime() - lockDate.getTime()) / 1000;

    return diffSeconds > eventLockTTL;
  }
}
