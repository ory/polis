import * as redis from 'redis';
import {
  DatabaseDriver,
  DatabaseOption,
  Encrypted,
  Index,
  Records,
  RequiredLogger,
  SortOrder,
} from '../typings';
import * as dbutils from './utils';

class Redis implements DatabaseDriver {
  private options: DatabaseOption;
  private client!: any;
  private logger: RequiredLogger;

  constructor(options: DatabaseOption, logger: RequiredLogger) {
    this.options = options;
    this.logger = logger;
  }

  async init(): Promise<Redis> {
    const opts = {};

    if (this.options && this.options.url) {
      opts['url'] = this.options.url;
    }

    this.client = redis.createClient(opts);
    this.client.on('error', (err: any) => this.logger.info('Redis Client Error', err));

    await this.client.connect();

    return this;
  }

  async get(namespace: string, key: string): Promise<any> {
    const res = await this.client.get(dbutils.key(namespace, key));
    if (res) {
      return JSON.parse(res);
    }

    return null;
  }

  async getAll(
    namespace: string,
    pageOffset?: number,
    pageLimit?: number,
    _?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    const sortedSetKey = dbutils.keyFromParts(dbutils.createdAtPrefix, namespace);

    const { offset, limit: count } = dbutils.normalizeOffsetAndLimit({
      pageOffset,
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });

    const zRangeOptions = {
      BY: 'SCORE',
      REV: sortOrder === 'ASC',
      LIMIT: {
        offset,
        count,
      },
    };

    const elements =
      sortOrder === 'ASC'
        ? await this.client.zRange(sortedSetKey, +Infinity, -Infinity, zRangeOptions)
        : await this.client.zRange(sortedSetKey, -Infinity, +Infinity, zRangeOptions);

    if (elements.length === 0) {
      return { data: [] };
    }

    const keyArray = elements.map((element) => {
      return dbutils.keyFromParts(namespace, element);
    });

    const records: string[] = [];
    const values = await this.client.MGET(keyArray);

    for (let i = 0; i < values.length; i++) {
      if (!values[i]) {
        // delete zadd
        this.client.ZREM(dbutils.keyFromParts(dbutils.createdAtPrefix, namespace), elements[i]);
        continue;
      }

      const valueObject = JSON.parse(values[i].toString());
      if (valueObject !== null && valueObject !== '') {
        records.push(valueObject);
      }
    }

    return { data: records };
  }

  async getByIndex(
    namespace: string,
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    _?: string
  ): Promise<Records> {
    const { offset: skip, limit } = dbutils.normalizeOffsetAndLimit({
      pageOffset,
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });
    let take = limit;

    let count = 0;
    take! += skip!;
    const returnValue: string[] = [];
    const keyArray: string[] = [];
    const idxKey = dbutils.keyForIndex(namespace, idx);
    const dbKeys = await this.client.sMembers(dbutils.keyFromParts(dbutils.indexPrefix, idxKey));
    for await (const { value } of this.client.zScanIterator(
      dbutils.keyFromParts(dbutils.createdAtPrefix, namespace),
      count + 1
    )) {
      if (dbKeys.indexOf(value) !== -1) {
        if (count >= take!) {
          break;
        }
        if (count >= skip!) {
          keyArray.push(dbutils.keyFromParts(namespace, value));
        }
        count++;
      }
    }
    if (keyArray.length > 0) {
      const values = await this.client.MGET(keyArray);
      for (let i = 0; i < values.length; i++) {
        if (!values[i]) {
          continue;
        }

        const valueObject = JSON.parse(values[i].toString());
        if (valueObject !== null && valueObject !== '') {
          returnValue.push(valueObject);
        }
      }
    }
    return { data: returnValue || [] };
  }

  async put(namespace: string, key: string, val: Encrypted, ttl = 0, ...indexes: any[]): Promise<void> {
    let tx = this.client.multi();
    const k = dbutils.key(namespace, key);

    tx = tx.set(k, JSON.stringify(val));

    if (ttl) {
      tx = tx.expire(k, ttl);
    }

    // no ttl support for secondary indexes
    for (const idx of indexes || []) {
      const idxKey = dbutils.keyForIndex(namespace, idx);
      tx = tx.sAdd(dbutils.keyFromParts(dbutils.indexPrefix, idxKey), key);
      tx = tx.sAdd(dbutils.keyFromParts(dbutils.indexPrefix, k), idxKey);
    }
    const timestamp = Number(Date.now());
    // Converting Timestamp in negative so that when we get the value,
    // it will be found in reverse order (descending order).
    const negativeTimestamp = -Math.abs(timestamp);
    const value = await this.client.get(k);
    if (!value) {
      tx = tx.zAdd(dbutils.keyFromParts(dbutils.createdAtPrefix, namespace), [
        { score: negativeTimestamp, value: key },
      ]);
    }
    await tx.exec();
  }

  async delete(namespace: string, key: string): Promise<any> {
    let tx = this.client.multi();
    const k = dbutils.key(namespace, key);
    tx = tx.del(k);

    const idxKey = dbutils.keyFromParts(dbutils.indexPrefix, k);
    // delete secondary indexes and then the mapping of the seconary indexes
    const dbKeys = await this.client.sMembers(idxKey);
    for (const dbKey of dbKeys || []) {
      tx.sRem(dbutils.keyFromParts(dbutils.indexPrefix, dbKey), key);
    }
    tx.ZREM(dbutils.keyFromParts(dbutils.createdAtPrefix, namespace), key);
    tx.del(idxKey);

    return await tx.exec();
  }

  async deleteMany(namespace: string, keys: string[]): Promise<void> {
    if (keys.length === 0) {
      return;
    }

    let tx = this.client.multi();

    for (const key of keys) {
      const k = dbutils.key(namespace, key);

      tx = tx.del(k);

      const idxKey = dbutils.keyFromParts(dbutils.indexPrefix, k);
      const dbKeys = await this.client.sMembers(idxKey);

      for (const dbKey of dbKeys || []) {
        tx.sRem(dbutils.keyFromParts(dbutils.indexPrefix, dbKey), key);
      }

      tx.ZREM(dbutils.keyFromParts(dbutils.createdAtPrefix, namespace), key);

      tx.del(idxKey);
    }

    await tx.exec();
  }

  async close(): Promise<void> {
    await this.client.quit();
  }

  getStats(): Record<string, number> {
    // no-op
    return {};
  }
}

export default {
  new: async (options: { db: DatabaseOption; logger: RequiredLogger }): Promise<Redis> => {
    return await new Redis(options.db, options.logger).init();
  },
};
