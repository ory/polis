// This is an in-memory implementation to be used with testing and prototyping only

import { DatabaseDriver, DatabaseOption, Index, Encrypted, Records, SortOrder } from '../typings';
import * as dbutils from './utils';

class Mem implements DatabaseDriver {
  private options: DatabaseOption;
  private store: any;
  private indexes: any;
  private cleanup: any;
  private ttlStore: any;
  private ttlCleanup: any;
  private timerId: any;

  constructor(options: DatabaseOption) {
    this.options = options;
  }

  async init(): Promise<Mem> {
    this.store = {}; // map of key, value
    this.indexes = {}; // map of key, Set
    this.cleanup = {}; // map of indexes for cleanup when store key is deleted
    this.ttlStore = {}; // map of key to ttl

    if (this.options.ttl) {
      this.ttlCleanup = async () => {
        const now = Date.now();
        for (const k in this.ttlStore) {
          if (this.ttlStore[k].expiresAt < now) {
            await this.delete(this.ttlStore[k].namespace, this.ttlStore[k].key);
          }
        }

        if (this.options.ttl) {
          this.timerId = setTimeout(this.ttlCleanup, this.options.ttl * 1000);
        }
      };

      this.timerId = setTimeout(this.ttlCleanup, this.options.ttl * 1000);
    }

    return this;
  }

  async get(namespace: string, key: string): Promise<any> {
    const res = this.store[dbutils.key(namespace, key)];
    if (res) {
      return res;
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
    const returnValue: string[] = [];

    const { offset: skip, limit } = dbutils.normalizeOffsetAndLimit({
      pageOffset,
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });

    let take = limit;
    let count = 0;

    take! += skip!;

    if (namespace) {
      const index = dbutils.keyFromParts(dbutils.createdAtPrefix, namespace);

      if (this.indexes[index] === undefined) {
        return { data: [] };
      }

      const val: string[] = Array.from(this.indexes[index]);
      const iterator: IterableIterator<string> = sortOrder === 'ASC' ? val.values() : val.reverse().values();

      for (const value of iterator) {
        if (count >= take!) {
          break;
        }

        if (count >= skip!) {
          returnValue.push(this.store[dbutils.keyFromParts(namespace, value)]);
        }

        count++;
      }
    }

    return { data: returnValue || [] };
  }

  async getByIndex(
    namespace: string,
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    _?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    const { offset: skip, limit } = dbutils.normalizeOffsetAndLimit({
      pageOffset,
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });

    let take = limit;

    let count = 0;

    take! += skip!;
    const dbKeys = Array.from((await this.indexes[dbutils.keyForIndex(namespace, idx)]) || []) as string[];
    const iterator: IterableIterator<string> =
      sortOrder === 'ASC' ? dbKeys.values() : dbKeys.reverse().values();
    const ret: string[] = [];
    for (const dbKey of iterator || []) {
      if (count >= take!) {
        break;
      }
      if (count >= skip!) {
        ret.push(await this.get(namespace, dbKey));
      }

      count++;
    }

    return { data: ret };
  }

  async put(namespace: string, key: string, val: Encrypted, ttl = 0, ...indexes: any[]): Promise<any> {
    const k = dbutils.key(namespace, key);

    this.store[k] = val;

    if (ttl) {
      this.ttlStore[k] = {
        namespace,
        key,
        expiresAt: Date.now() + ttl * 1000,
      };
    }
    // no ttl support for secondary indexes
    for (const idx of indexes || []) {
      const idxKey = dbutils.keyForIndex(namespace, idx);
      let set = this.indexes[idxKey];
      if (!set) {
        set = new Set();
        this.indexes[idxKey] = set;
      }

      set.add(key);
      const cleanupKey = dbutils.keyFromParts(dbutils.indexPrefix, k);
      let cleanup = this.cleanup[cleanupKey];
      if (!cleanup) {
        cleanup = new Set();
        this.cleanup[cleanupKey] = cleanup;
      }

      cleanup.add(idxKey);
    }
    let createdAtSet = this.indexes[dbutils.keyFromParts(dbutils.createdAtPrefix, namespace)];
    if (!createdAtSet) {
      createdAtSet = new Set();
      this.indexes[dbutils.keyFromParts(dbutils.createdAtPrefix, namespace)] = createdAtSet;
      this.store['createdAt'] = new Date().toISOString();
      createdAtSet.add(key);
    } else {
      if (!this.indexes[dbutils.keyFromParts(dbutils.createdAtPrefix, namespace)].has(key)) {
        createdAtSet.add(key);
        this.store['createdAt'] = new Date().toISOString();
      }
    }
  }

  async delete(namespace: string, key: string): Promise<any> {
    const k = dbutils.key(namespace, key);

    delete this.store[k];

    const idxKey = dbutils.keyFromParts(dbutils.indexPrefix, k);
    // delete secondary indexes and then the mapping of the seconary indexes
    const dbKeys = this.cleanup[idxKey];

    for (const dbKey of dbKeys || []) {
      this.indexes[dbKey] && this.indexes[dbKey].delete(key);
    }
    if (this.indexes[dbutils.keyFromParts(dbutils.createdAtPrefix, namespace)]) {
      this.indexes[dbutils.keyFromParts(dbutils.createdAtPrefix, namespace)].delete(key);
    }
    delete this.cleanup[idxKey];
    delete this.ttlStore[k];
  }

  async deleteMany(namespace: string, keys: string[]): Promise<void> {
    if (keys.length === 0) {
      return;
    }

    for (const key of keys) {
      await this.delete(namespace, key);
    }
  }

  async close(): Promise<void> {
    // no-op
  }

  getStats(): Record<string, number> {
    // no-op
    return {};
  }
}

export default {
  new: async (options: { db: DatabaseOption }) => {
    return await new Mem(options.db).init();
  },
};
