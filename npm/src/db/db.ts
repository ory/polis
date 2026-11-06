import {
  DatabaseDriver,
  DatabaseDriverOption,
  DatabaseOption,
  Encrypted,
  EncryptionKey,
  Index,
  Records,
  RequiredLogger,
  SortOrder,
  Storable,
} from '../typings';
import * as encrypter from './encrypter';
import mem from './mem';
import mongo from './mongo';
import redis from './redis';
import sql from './sql/sql';
import store from './store';
import dynamodb from './dynamoDb';
import * as metrics from '../opentelemetry/metrics';

import { JacksonStore } from './sql/entity/JacksonStore';
import { JacksonIndex } from './sql/entity/JacksonIndex';
import { JacksonTTL } from './sql/entity/JacksonTTL';

import { JacksonStore as JacksonStorePlanetscale } from './planetscale/entity/JacksonStore';
import { JacksonIndex as JacksonIndexPlanetscale } from './planetscale/entity/JacksonIndex';
import { JacksonTTL as JacksonTTLPlanetscale } from './planetscale/entity/JacksonTTL';

import { JacksonStore as JacksonStoreMSSQL } from './sql/mssql/entity/JacksonStore';
import { JacksonIndex as JacksonIndexMSSQL } from './sql/mssql/entity/JacksonIndex';
import { JacksonTTL as JacksonTTLMSSQL } from './sql/mssql/entity/JacksonTTL';

import { JacksonStore as JacksonStoreSQLITE } from './sql/sqlite/entity/JacksonStore';
import { JacksonIndex as JacksonIndexSQLITE } from './sql/sqlite/entity/JacksonIndex';
import { JacksonTTL as JacksonTTLSQLITE } from './sql/sqlite/entity/JacksonTTL';

import { JacksonStore as JacksonStoreMariaDB } from './sql/mariadb/entity/JacksonStore';
import { JacksonIndex as JacksonIndexMariaDB } from './sql/mariadb/entity/JacksonIndex';
import { JacksonTTL as JacksonTTLMariaDB } from './sql/mariadb/entity/JacksonTTL';

const STATS_INTERVAL = 30 * 1000;

const decrypt = (res: Encrypted, encryptionKey: EncryptionKey): unknown => {
  if (res.iv && res.tag) {
    return JSON.parse(encrypter.decrypt(res.value, res.iv, res.tag, encryptionKey));
  }

  return JSON.parse(res.value);
};

class DB implements DatabaseDriver {
  private db: DatabaseDriver;
  private encryptionKey: EncryptionKey;
  private statsIntervalId: NodeJS.Timeout;
  private logger: RequiredLogger;

  constructor(db: DatabaseDriver, encryptionKey: EncryptionKey, logger: RequiredLogger) {
    this.db = db;
    this.encryptionKey = encryptionKey;
    this.logger = logger;

    this.statsIntervalId = setInterval(async () => this.publishStats(), STATS_INTERVAL);
  }

  async get(namespace: string, key: string): Promise<unknown> {
    const res = await this.db.get(namespace, key);

    if (!res) {
      return null;
    }

    return decrypt(res, this.encryptionKey);
  }

  async getAll(
    namespace: string,
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    const res = await this.db.getAll(namespace, pageOffset, pageLimit, pageToken, sortOrder);
    const encryptionKey = this.encryptionKey;
    return {
      data: res.data.map((r) => {
        return decrypt(r, encryptionKey);
      }),
      pageToken: res.pageToken,
    };
  }

  async getByIndex(
    namespace: string,
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    const res = await this.db.getByIndex(namespace, idx, pageOffset, pageLimit, pageToken, sortOrder);
    const encryptionKey = this.encryptionKey;
    return {
      data: res.data.map((r) => {
        return decrypt(r, encryptionKey);
      }),
      pageToken: res.pageToken,
    };
  }

  async getCount(namespace: string, idx?: Index): Promise<number | undefined> {
    if (typeof this.db.getCount !== 'function') {
      return;
    }
    return await this.db.getCount(namespace, idx);
  }

  // ttl is in seconds
  async put(namespace: string, key: string, val: unknown, ttl = 0, ...indexes: Index[]): Promise<unknown> {
    const dbVal = this.encryptionKey
      ? encrypter.encrypt(JSON.stringify(val), this.encryptionKey)
      : { value: JSON.stringify(val) };

    return await this.db.put(namespace, key, dbVal, ttl, ...indexes);
  }

  async delete(namespace: string, key: string): Promise<unknown> {
    return await this.db.delete(namespace, key);
  }

  async deleteMany(namespace: string, keys: string[]): Promise<void> {
    return await this.db.deleteMany(namespace, keys);
  }

  async close(): Promise<void> {
    // Flush stats one last time
    this.publishStats();

    await this.db.close();
    clearInterval(this.statsIntervalId);
  }

  getStats(): Record<string, number> {
    return this.db.getStats();
  }

  store(namespace: string, ttl = 0): Storable {
    return store.new(namespace, this, ttl);
  }

  private publishStats() {
    try {
      const stats = this.getStats();
      if (stats.applicationName) {
        if (stats.max >= 0) {
          metrics.gauge('dbMaxConnections', stats.max, { db_name: stats.applicationName });
        }
        if (stats.total >= 0) {
          metrics.gauge('dbTotalConnections', stats.total, { db_name: stats.applicationName });
        }
        if (stats.idle >= 0) {
          metrics.gauge('dbIdleConnections', stats.idle, { db_name: stats.applicationName });
        }
        if (stats.waiting >= 0) {
          metrics.gauge('dbWaitingConnections', stats.waiting, { db_name: stats.applicationName });
        }
      }
    } catch (err) {
      this.logger.error(`error getting db stats: ${err}`);
    }
  }
}

const _new = async (options: { db: DatabaseOption | DatabaseDriverOption; logger: RequiredLogger }) => {
  const dbOpts = options.db;
  const encryptionKey = dbOpts.encryptionKey
    ? dbOpts.encryptionKey.length === 32
      ? Buffer.from(dbOpts.encryptionKey, 'latin1')
      : Buffer.from(dbOpts.encryptionKey, 'base64')
    : null;

  if ('driver' in dbOpts) {
    return new DB(dbOpts.driver, encryptionKey, options.logger);
  }

  switch (dbOpts.engine) {
    case 'redis':
      return new DB(await redis.new(options), encryptionKey, options.logger);
    case 'sql':
      switch (dbOpts.type) {
        case 'mssql':
          return new DB(
            await sql.new(options, {
              JacksonStore: JacksonStoreMSSQL,
              JacksonIndex: JacksonIndexMSSQL,
              JacksonTTL: JacksonTTLMSSQL,
            }),
            encryptionKey,
            options.logger
          );
        case 'mariadb':
        case 'mysql':
          return new DB(
            await sql.new(options, {
              JacksonStore: JacksonStoreMariaDB,
              JacksonIndex: JacksonIndexMariaDB,
              JacksonTTL: JacksonTTLMariaDB,
            }),
            encryptionKey,
            options.logger
          );
        case 'sqlite':
          return new DB(
            await sql.new(options, {
              JacksonStore: JacksonStoreSQLITE,
              JacksonIndex: JacksonIndexSQLITE,
              JacksonTTL: JacksonTTLSQLITE,
            }),
            encryptionKey,
            options.logger
          );
        default:
          return new DB(
            await sql.new(options, {
              JacksonStore,
              JacksonIndex,
              JacksonTTL,
            }),
            encryptionKey,
            options.logger
          );
      }
    case 'planetscale':
      return new DB(
        await sql.new(options, {
          JacksonStore: JacksonStorePlanetscale,
          JacksonIndex: JacksonIndexPlanetscale,
          JacksonTTL: JacksonTTLPlanetscale,
        }),
        encryptionKey,
        options.logger
      );
    case 'mongo':
      return new DB(await mongo.new(options), encryptionKey, options.logger);
    case 'mem':
      return new DB(await mem.new(options), encryptionKey, options.logger);
    case 'dynamodb':
      return new DB(await dynamodb.new(options), encryptionKey, options.logger);
    default:
      throw new Error('unsupported db engine: ' + dbOpts.engine);
  }
};

const g = global as any;

export default {
  new: async (
    options: { db: DatabaseOption | DatabaseDriverOption; logger: RequiredLogger },
    noCache = false
  ) => {
    if (g.__jacksonDb && !noCache) {
      return g.__jacksonDb;
    }

    g.__jacksonDb = new Promise((resolve, reject) => {
      _new(options).then(resolve).catch(reject);
    });

    return await g.__jacksonDb;
  },
};
