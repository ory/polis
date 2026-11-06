import { Collection, Db, MongoClient, Sort, UpdateOptions } from 'mongodb';
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

type _Document = {
  value: Encrypted;
  expiresAt?: Date;
  modifiedAt: string;
  namespace: string;
  indexes: string[];
};

class Mongo implements DatabaseDriver {
  private options: DatabaseOption;
  private client!: MongoClient;
  private collection!: Collection;
  private db!: Db;
  private logger: RequiredLogger;

  constructor(options: DatabaseOption, logger: RequiredLogger) {
    this.options = options;
    this.logger = logger;
  }

  async init(): Promise<Mongo> {
    const dbUrl = this.options.url as string;
    try {
      this.client = new MongoClient(dbUrl);
      await this.client.connect();
    } catch (err) {
      this.logger.error(`error connecting to engine: ${this.options.engine}, db: ${err}`);
      throw err;
    }

    this.db = this.client.db();
    this.collection = this.db.collection('jacksonStore');

    await this.collection.createIndex({ indexes: 1 });
    await this.collection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 1 });
    await this.collection.createIndex({ namespace: 1 });

    while (true) {
      try {
        if (!this.options.manualMigration) {
          await this.indexNamespace();
        }
        break;
      } catch (err) {
        this.logger.error(
          `error in index namespace execution for db engine: ${this.options.engine},  err: ${err}`
        );
        await dbutils.sleep(1000);
        continue;
      }
    }

    return this;
  }

  async indexNamespace() {
    const docs = await this.collection.find({ namespace: { $exists: false } }).toArray();
    const searchTerm = ':';

    for (const doc of docs || []) {
      const tokens2 = doc._id.toString().split(searchTerm).slice(0, 2);
      const namespace = tokens2.join(searchTerm);
      await this.collection.updateOne({ _id: doc._id }, { $set: { namespace } });
    }
  }

  async get(namespace: string, key: string): Promise<any> {
    const res = await this.collection.findOne({
      _id: dbutils.key(namespace, key) as any,
    });
    if (res && res.value) {
      return res.value;
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
    const { offset: skip, limit } = dbutils.normalizeOffsetAndLimit({
      pageOffset,
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });

    const docs = await this.collection
      .find(
        { namespace: namespace },
        {
          sort: { createdAt: sortOrder === 'ASC' ? 1 : -1 },
          skip,
          limit,
        }
      )
      .toArray();

    if (docs) {
      return { data: docs.map(({ value }) => value) };
    }

    return { data: [] };
  }

  async getByIndex(
    namespace: string,
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    _?: string,
    sortOrder?: SortOrder
  ): Promise<Records> {
    const sort: Sort = { createdAt: sortOrder === 'ASC' ? 'asc' : 'desc' };
    const { offset: skip, limit } = dbutils.normalizeOffsetAndLimit({
      pageOffset,
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });

    const docs = await this.collection
      .find(
        {
          indexes: dbutils.keyForIndex(namespace, idx),
        },
        {
          sort,
          skip,
          limit,
        }
      )
      .toArray();

    const ret: string[] = [];
    for (const doc of docs || []) {
      ret.push(doc.value);
    }

    return { data: ret };
  }

  async getCount(namespace: string, idx?: Index): Promise<number> {
    const count =
      idx !== undefined
        ? await this.collection.countDocuments(
            { indexes: dbutils.keyForIndex(namespace, idx) },
            { hint: 'indexes_1' }
          )
        : await this.collection.countDocuments({ namespace }, { hint: 'namespace_1' });
    return count;
  }

  async put(namespace: string, key: string, val: Encrypted, ttl = 0, ...indexes: any[]): Promise<void> {
    const doc = <_Document>{
      value: val,
    };

    if (ttl) {
      doc.expiresAt = new Date(Date.now() + ttl * 1000);
    }
    doc.namespace = namespace;
    // no ttl support for secondary indexes
    for (const idx of indexes || []) {
      const idxKey = dbutils.keyForIndex(namespace, idx);

      if (!doc.indexes) {
        doc.indexes = [];
      }
      doc.indexes.push(idxKey);
    }

    doc.modifiedAt = new Date().toISOString();
    await this.collection.updateOne(
      { _id: dbutils.key(namespace, key) as any },
      {
        $set: doc,
        $setOnInsert: {
          createdAt: new Date().toISOString(),
        },
      },
      { upsert: true } as UpdateOptions
    );
  }

  async delete(namespace: string, key: string): Promise<any> {
    return await this.collection.deleteOne({
      _id: dbutils.key(namespace, key) as any,
    });
  }

  async deleteMany(namespace: string, keys: string[]): Promise<void> {
    if (keys.length === 0) {
      return;
    }

    const dbKeys = keys.map((key) => dbutils.key(namespace, key)) as any[];

    await this.collection.deleteMany({
      _id: { $in: dbKeys },
    });
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  getStats(): Record<string, number> {
    // no-op
    return {};
  }
}

export default {
  new: async (options: { db: DatabaseOption; logger: RequiredLogger }): Promise<Mongo> => {
    return await new Mongo(options.db, options.logger).init();
  },
};
