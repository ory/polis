import {
  BatchWriteItemCommand,
  WriteRequest,
  CreateTableCommand,
  DeleteItemCommand,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  QueryCommand,
  UpdateTimeToLiveCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall, NativeAttributeValue } from '@aws-sdk/util-dynamodb';
import { DatabaseDriver, DatabaseOption, Encrypted, Index, Records } from '../typings';
import * as dbutils from './utils';

const getSeconds = (date: Date) => Math.floor(date.getTime() / 1000);

const tableName = 'jacksonStore';
const indexTableName = 'jacksonIndex';
const globalStoreKeyIndexName = 'storeKeyIndex';
const globalIndexKeyIndexName = 'indexKeyIndex';

const checkForTableExistsError = (err: any) => {
  if (
    err?.name !== 'ResourceInUseException' &&
    !err?.message?.includes('Cannot create preexisting table') &&
    !err?.message?.toLowerCase().includes('table already exists')
  ) {
    throw err;
  }
};

class DynamoDB implements DatabaseDriver {
  private options: DatabaseOption;
  private client!: DynamoDBClient;

  constructor(options: DatabaseOption) {
    this.options = options;
  }

  async init(): Promise<DynamoDB> {
    this.client = new DynamoDBClient({
      endpoint: this.options.url,
      region: this.options.dynamodb!.region!,
    });
    try {
      await this.client.send(
        new CreateTableCommand({
          KeySchema: [
            {
              AttributeName: 'namespace',
              KeyType: 'HASH',
            },
            {
              AttributeName: 'key',
              KeyType: 'RANGE',
            },
          ],
          AttributeDefinitions: [
            {
              AttributeName: 'namespace',
              AttributeType: 'S',
            },
            {
              AttributeName: 'key',
              AttributeType: 'S',
            },
          ],
          ProvisionedThroughput: {
            ReadCapacityUnits: this.options.dynamodb!.readCapacityUnits!,
            WriteCapacityUnits: this.options.dynamodb!.writeCapacityUnits!,
          },
          TableName: tableName,
        })
      );

      await this.client.send(
        new UpdateTimeToLiveCommand({
          TableName: tableName,
          TimeToLiveSpecification: {
            AttributeName: 'expiresAt',
            Enabled: true,
          },
        })
      );
    } catch (err: any) {
      checkForTableExistsError(err);
    }
    try {
      await this.client.send(
        new CreateTableCommand({
          KeySchema: [
            {
              AttributeName: 'key',
              KeyType: 'HASH',
            },
            {
              AttributeName: 'storeKey',
              KeyType: 'RANGE',
            },
          ],
          AttributeDefinitions: [
            {
              AttributeName: 'key',
              AttributeType: 'S',
            },
            {
              AttributeName: 'storeKey',
              AttributeType: 'S',
            },
          ],
          GlobalSecondaryIndexes: [
            {
              IndexName: globalIndexKeyIndexName,
              KeySchema: [
                {
                  AttributeName: 'key',
                  KeyType: 'HASH',
                },
              ],
              Projection: {
                ProjectionType: 'ALL',
              },
              ProvisionedThroughput: {
                ReadCapacityUnits: this.options.dynamodb!.readCapacityUnits!,
                WriteCapacityUnits: this.options.dynamodb!.writeCapacityUnits!,
              },
            },
            {
              IndexName: globalStoreKeyIndexName,
              KeySchema: [
                {
                  AttributeName: 'storeKey',
                  KeyType: 'HASH',
                },
              ],
              Projection: {
                ProjectionType: 'ALL',
              },
              ProvisionedThroughput: {
                ReadCapacityUnits: this.options.dynamodb!.readCapacityUnits!,
                WriteCapacityUnits: this.options.dynamodb!.writeCapacityUnits!,
              },
            },
          ],
          ProvisionedThroughput: {
            ReadCapacityUnits: this.options.dynamodb!.readCapacityUnits!,
            WriteCapacityUnits: this.options.dynamodb!.writeCapacityUnits!,
          },
          TableName: indexTableName,
        })
      );
    } catch (err: any) {
      checkForTableExistsError(err);
    }
    return this;
  }

  // internal get without dbutils.Key
  async _get(namespace: string, key: string): Promise<any> {
    const res = await this.client.send(
      new GetItemCommand({ Key: marshall({ namespace, key }), TableName: tableName })
    );

    // Double check that the item has not expired
    const now = getSeconds(new Date());

    const item = res.Item ? unmarshall(res.Item) : null;

    if (item?.expiresAt < now) {
      return null;
    }

    if (item && item.value) {
      return JSON.parse(item.value);
    }

    return null;
  }

  async get(namespace: string, key: string): Promise<any> {
    return this._get(namespace, dbutils.key(namespace, key));
  }

  async getAll(namespace: string, _?: number, pageLimit?: number, pageToken?: string): Promise<Records> {
    const { limit: Limit } = dbutils.normalizeOffsetAndLimit({
      pageLimit,
      maxLimit: this.options.pageLimit!,
    });
    const res = await this.client.send(
      new QueryCommand({
        KeyConditionExpression: 'namespace = :namespace',
        ExpressionAttributeValues: {
          ':namespace': { S: namespace },
        },
        TableName: tableName,
        Limit,
        ExclusiveStartKey: pageToken ? JSON.parse(Buffer.from(pageToken, 'base64').toString()) : undefined,
      })
    );

    const newPageToken = res.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(res.LastEvaluatedKey)).toString('base64')
      : undefined;
    const items: Encrypted[] = [];
    for (const item of res.Items || []) {
      const ns = item.namespace?.S;
      const k = item.key?.S;
      const value = item.value?.S;
      if (ns && k && value) {
        const val = JSON.parse(value);
        if (val) {
          items.push(val);
        }
      }
    }

    return { data: items, pageToken: newPageToken };
  }

  // dynamodb pagination cannot care about pageOffset and pageLimit here, we let it handle it on it's own
  async getByIndex(
    namespace: string,
    idx: Index,
    _?: number,
    __?: number,
    pageToken?: string
  ): Promise<Records> {
    const res = await this.client.send(
      new QueryCommand({
        KeyConditionExpression: '#key = :key',
        ExpressionAttributeNames: {
          '#key': 'key',
        },
        ExpressionAttributeValues: {
          ':key': { S: dbutils.keyForIndex(namespace, idx) },
        },
        TableName: indexTableName,
        IndexName: globalIndexKeyIndexName,
        ExclusiveStartKey: pageToken ? JSON.parse(Buffer.from(pageToken, 'base64').toString()) : undefined,
      })
    );

    const newPageToken = res.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(res.LastEvaluatedKey)).toString('base64')
      : undefined;
    const items: Encrypted[] = [];
    for (const item of res.Items || []) {
      const ns = item.namespace?.S;
      const sk = item.storeKey?.S;
      if (ns && sk) {
        const val = await this._get(ns, sk); // use internal get to avoid double keying
        if (val) {
          items.push({
            value: val.value,
            iv: val.iv,
            tag: val.tag,
          });
        }
      }
    }

    return { data: items, pageToken: newPageToken };
  }

  async put(namespace: string, key: string, val: Encrypted, ttl = 0, ...indexes: any[]): Promise<void> {
    const dbKey = dbutils.key(namespace, key);
    const now = getSeconds(new Date());
    const doc: Record<string, NativeAttributeValue> = {
      namespace,
      key: dbKey,
      value: JSON.stringify(val),
      createdAt: now,
    };

    if (ttl) {
      const ttlDate = new Date(Date.now() + ttl * 1000);
      doc.expiresAt = getSeconds(ttlDate);
    }

    const indexWrites: WriteRequest[] = [];
    // no ttl support for secondary indexes
    for (const idx of indexes || []) {
      const idxKey = dbutils.keyForIndex(namespace, idx);

      indexWrites.push({
        PutRequest: {
          Item: marshall({
            namespace,
            key: idxKey,
            storeKey: dbKey,
          }),
        },
      });
    }

    if (indexWrites.length > 0) {
      const reqItems: Record<string, WriteRequest[]> = {};
      reqItems[indexTableName] = indexWrites;
      await this.client.send(
        new BatchWriteItemCommand({
          RequestItems: reqItems,
        })
      );
    }

    await this.client.send(
      new PutItemCommand({
        TableName: tableName,
        Item: marshall(doc),
      })
    );
  }

  async delete(namespace: string, key: string): Promise<any> {
    const dbKey = dbutils.key(namespace, key);
    await this.client.send(
      new DeleteItemCommand({
        TableName: tableName,
        Key: marshall({ namespace, key: dbKey }),
      })
    );

    const res = await this.client.send(
      new QueryCommand({
        KeyConditionExpression: 'storeKey = :storeKey',
        ExpressionAttributeValues: {
          ':storeKey': { S: dbKey },
        },
        TableName: indexTableName,
        IndexName: globalStoreKeyIndexName,
      })
    );

    for (const item of res.Items || []) {
      const k = item.key?.S;
      await this.client.send(
        new DeleteItemCommand({
          TableName: indexTableName,
          Key: marshall({ key: k, storeKey: dbKey }),
        })
      );
    }
  }

  async deleteMany(namespace: string, keys: string[]): Promise<void> {
    if (keys.length === 0) {
      return;
    }

    await Promise.all(keys.map((key) => this.delete(namespace, key)));
  }

  async close(): Promise<void> {
    await this.client.destroy();
  }

  getStats(): Record<string, number> {
    // no-op
    return {};
  }
}

export default {
  new: async (options: { db: DatabaseOption }): Promise<DynamoDB> => {
    return await new DynamoDB(options.db).init();
  },
};
