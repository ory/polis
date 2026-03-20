import { Index, Records, SortOrder, Storable } from '../typings';
import * as dbutils from './utils';

class Store implements Storable {
  private namespace: string;
  private db: any;
  private ttl: number;

  constructor(namespace: string, db: any, ttl = 0) {
    this.namespace = namespace;
    this.db = db;
    this.ttl = ttl;
  }

  async get(key: string): Promise<any> {
    return await this.db.get(this.namespace, dbutils.keyDigest(key));
  }

  async getAll(
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    return await this.db.getAll(this.namespace, pageOffset, pageLimit, pageToken, sortOrder);
  }

  async getByIndex(
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    idx.value = dbutils.keyDigest(idx.value);

    return await this.db.getByIndex(this.namespace, idx, pageOffset, pageLimit, pageToken, sortOrder);
  }

  async getCount(idx?: Index) {
    idx && (idx.value = dbutils.keyDigest(idx.value));
    return await this.db.getCount(this.namespace, idx);
  }

  async put(key: string, val: any, ...indexes: Index[]): Promise<any> {
    indexes = (indexes || []).map((idx) => {
      idx.value = dbutils.keyDigest(idx.value);
      return idx;
    });

    return await this.db.put(this.namespace, dbutils.keyDigest(key), val, this.ttl, ...indexes);
  }

  async delete(key: string): Promise<any> {
    return await this.db.delete(this.namespace, dbutils.keyDigest(key));
  }

  async deleteMany(keys: string[]): Promise<void> {
    return await this.db.deleteMany(
      this.namespace,
      keys.map((key) => dbutils.keyDigest(key))
    );
  }
}

export default {
  new: (namespace: string, db: any, ttl = 0): Storable => {
    return new Store(namespace, db, ttl);
  },
};
