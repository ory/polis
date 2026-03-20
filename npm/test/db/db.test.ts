import { DatabaseOption, EncryptionKey, Storable, DatabaseDriver } from '../../src/typings';
import tap from 'tap';
import DB from '../../src/db/db';
import { randomBytes } from 'crypto';

const encryptionKey: EncryptionKey = 'IDv0Q/4meshxZOvDhtZUWsHMRf9VCvBt+PoB8z3bZV8=';

const dbObjs: { [key: string]: DatabaseDriver } = {};
const connectionStores: Storable[] = [];
const ttlStores: Storable[] = [];
const ttl = 2;

const record1 = {
  id: '1',
  name: 'Deepak',
  city: 'London',
};

const record2 = {
  id: '2',
  name: 'Sama',
  city: 'London',
};

const record3 = {
  id: '3',
  name: 'Samuel Jackson',
  city: 'Delhi',
};

const records = [record1, record2, record3];

const memDbConfig = <DatabaseOption>{
  engine: 'mem',
  ttl: 1,
  pageLimit: 2,
};

const redisDbConfig = <DatabaseOption>{
  engine: 'redis',
  url: 'redis://localhost:6379',
  pageLimit: 2,
};

const postgresDbConfig = <DatabaseOption>{
  engine: 'sql',
  url: 'postgresql://postgres:postgres@localhost:5432/postgres',
  type: 'postgres',
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
};

const cockroachDbConfig = <DatabaseOption>{
  engine: 'sql',
  url: 'cockroachdb://root@localhost:26257/postgres?sslmode=disable',
  type: 'cockroachdb',
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
};

const mongoDbConfig = <DatabaseOption>{
  engine: 'mongo',
  url: 'mongodb://localhost:27017/jackson',
  pageLimit: 2,
};

const mysqlDbConfig = <DatabaseOption>{
  engine: 'sql',
  url: 'mysql://root:mysql@localhost:3307/mysql',
  type: 'mysql',
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
};

const planetscaleDbConfig = <DatabaseOption>{
  engine: 'planetscale',
  url: process.env.PLANETSCALE_URL,
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
  // ssl: {
  //   rejectUnauthorized: true,
  // },
};

const mariadbDbConfig = <DatabaseOption>{
  engine: 'sql',
  url: 'mariadb://root@localhost:3306/mysql',
  type: 'mariadb',
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
};

const mssqlDbConfig = <DatabaseOption>{
  engine: 'sql',
  type: 'mssql',
  url: 'sqlserver://localhost:1433;database=master;username=sa;password=123ABabc!',
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
};

const dynamoDbConfig = <DatabaseOption>{
  engine: 'dynamodb',
  url: process.env.DYNAMODB_URL,
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
  dynamodb: {
    region: 'us-east-1',
    readCapacityUnits: 5,
    writeCapacityUnits: 5,
  },
};

const sqliteConfig = <DatabaseOption>{
  engine: 'sql',
  type: 'sqlite',
  url: 'file:///var/tmp/test-sqlite-database.db',
  ttl: 1,
  cleanupLimit: 10,
  pageLimit: 2,
};

const dbs = [
  {
    ...memDbConfig,
  },
  {
    ...memDbConfig,
    encryptionKey,
  },
  {
    ...redisDbConfig,
  },
  {
    ...redisDbConfig,
    encryptionKey,
  },
  {
    ...postgresDbConfig,
  },
  {
    ...postgresDbConfig,
    encryptionKey,
  },
  {
    ...cockroachDbConfig,
  },
  {
    ...cockroachDbConfig,
    encryptionKey,
  },
  {
    ...mongoDbConfig,
  },
  {
    ...mongoDbConfig,
    encryptionKey,
  },
  {
    ...mysqlDbConfig,
  },
  {
    ...mysqlDbConfig,
    encryptionKey,
  },
  {
    ...mariadbDbConfig,
  },
  {
    ...mariadbDbConfig,
    encryptionKey,
  },
  {
    ...mssqlDbConfig,
  },
  {
    ...mssqlDbConfig,
    encryptionKey,
  },
  {
    ...sqliteConfig,
  },
  {
    ...sqliteConfig,
    encryptionKey,
  },
];

if (process.env.PLANETSCALE_URL) {
  dbs.push(
    {
      ...planetscaleDbConfig,
    },
    {
      ...planetscaleDbConfig,
      encryptionKey,
    }
  );
}

if (process.env.DYNAMODB_URL) {
  dbs.push(
    {
      ...dynamoDbConfig,
    },
    {
      ...dynamoDbConfig,
      encryptionKey,
    }
  );
}

tap.before(async () => {
  for (const idx in dbs) {
    const opts = dbs[idx];
    const db = await DB.new({ db: opts, logger: console }, true);
    dbObjs[opts.engine! + (opts.type ? opts.type : '')] = db;

    const randomSession = Date.now();
    connectionStores.push(db.store('saml:config:' + randomSession + randomBytes(4).toString('hex')));
    ttlStores.push(db.store('oauth:session:' + randomSession + randomBytes(4).toString('hex'), ttl));
  }
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('dbs', async () => {
  for (const idx in connectionStores) {
    const connectionStore = connectionStores[idx];
    const ttlStore = ttlStores[idx];
    const dbEngine = dbs[idx].engine!;
    let dbType = dbEngine;
    if (dbs[idx].type) {
      dbType += ': ' + dbs[idx].type;
    }

    tap.test('put(): ' + dbType, async () => {
      await connectionStore.put(
        record1.id,
        record1,
        {
          // secondary index on city
          name: 'city',
          value: record1.city,
        },
        {
          // secondary index on name
          name: 'name',
          value: record1.name,
        }
      );

      // wait 100ms to ensure that the record is written with a different timestamp
      await new Promise((resolve) => setTimeout(resolve, 100));

      await connectionStore.put(
        record2.id,
        record2,
        {
          // secondary index on city
          name: 'city',
          value: record2.city,
        },
        {
          // secondary index on name
          name: 'name',
          value: record2.name,
        }
      );

      // wait 100ms to ensure that the record is written with a different timestamp
      await new Promise((resolve) => setTimeout(resolve, 100));

      await connectionStore.put(
        record3.id,
        record3,
        {
          // secondary index on city
          name: 'city',
          value: record3.city,
        },
        {
          // secondary index on name
          name: 'name',
          value: record3.name,
        }
      );
    });

    tap.test('get(): ' + dbType, async (t) => {
      const ret1 = await connectionStore.get(record1.id);
      const ret2 = await connectionStore.get(record2.id);

      t.same(ret1, record1, 'unable to get record1');
      t.same(ret2, record2, 'unable to get record2');
    });

    tap.test('getAll(): ' + dbType, async (t) => {
      const testMessage =
        dbEngine === 'dynamodb' // dynamodb doesn't support sort order
          ? 'should return all the records upto options.pageLimit'
          : 'should return all the records upto options.pageLimit in DESC order by creation time';
      const wanted = dbEngine === 'dynamodb' ? records.slice(1, 3) : [...records].reverse().slice(0, 2);
      // getAll without pagination params
      t.same((await connectionStore.getAll()).data, wanted, `without pagination params ` + testMessage);
      // getAll with pagination params
      t.same((await connectionStore.getAll(0, 2)).data, wanted, `with pagination params ` + testMessage);
      // getAll with pageLimit set to 0
      t.same((await connectionStore.getAll(0, 0)).data, wanted, `with pageLimit set to 0 ` + testMessage);
      // getAll with pageLimit > options.pageLimit
      t.same(
        (await connectionStore.getAll(0, 3)).data,
        wanted,
        `with pageLimit > options.pageLimit ` + testMessage
      );

      const oneRecordWithPagination = await connectionStore.getAll(0, 1);
      t.same(
        oneRecordWithPagination.data.length,
        1,
        "getAll pagination should get only 1 record, order doesn't matter"
      );

      const secondRecordWithPagination = await connectionStore.getAll(
        1,
        1,
        oneRecordWithPagination.pageToken
      );
      t.same(
        secondRecordWithPagination.data.length,
        1,
        "getAll pagination should get only 1 record, order doesn't matter"
      );

      if (!dbEngine.startsWith('dynamodb')) {
        const { data: sortedRecordsAsc } = await connectionStore.getAll(0, 2, undefined, 'ASC');
        t.match(sortedRecordsAsc, [record1, record2], 'records are sorted in ASC order');

        const { data: sortedRecordsDesc } = await connectionStore.getAll(0, 2, undefined, 'DESC');
        t.match(sortedRecordsDesc, [record3, record2], 'records are sorted in DESC order');
      }
    });

    tap.test('getByIndex(): ' + dbType, async (t) => {
      const ret1 = await connectionStore.getByIndex({
        name: 'name',
        value: record1.name,
      });

      const ret2 = await connectionStore.getByIndex({
        name: 'city',
        value: record1.city,
      });

      t.same(ret1.data, [record1], 'unable to get index "name"');
      t.same(
        ret2.data.sort((a, b) => a.id.localeCompare(b.id)),
        [record1, record2].sort((a, b) => a.id.localeCompare(b.id)),
        'unable to get index "city"'
      );

      const ret3 = await connectionStore.getByIndex(
        {
          name: 'city',
          value: record1.city,
        },
        0,
        1
      );
      const numRec = dbEngine === 'dynamodb' ? 2 : 1;
      t.same(
        ret3.data.length,
        numRec,
        `getByIndex pagination should get only ${numRec} record, order doesn't matter`
      );

      const ret4 = await connectionStore.getByIndex(
        {
          name: 'city',
          value: record1.city,
        },
        1,
        1,
        ret3.pageToken
      );
      t.same(
        ret4.data.length,
        numRec,
        `getByIndex pagination should get only ${numRec} record, order doesn't matter`
      );

      t.same(
        ret2.data.sort((a, b) => a.id.localeCompare(b.id)),
        dbEngine === 'dynamodb'
          ? ret3.data.sort((a, b) => a.id.localeCompare(b.id))
          : [ret3.data[0], ret4.data[0]].sort((a, b) => a.id.localeCompare(b.id)),
        'getByIndex pagination for index "city" failed'
      );

      // sort order tests
      if (!dbEngine.startsWith('dynamodb') && !dbEngine.startsWith('redis')) {
        const { data: sortedRecordsAsc } = await connectionStore.getByIndex(
          {
            name: 'city',
            value: record1.city,
          },
          undefined,
          undefined,
          undefined,
          'ASC'
        );
        t.match(sortedRecordsAsc, [record1, record2], 'records are sorted in ASC order');

        const { data: sortedRecordsDesc } = await connectionStore.getByIndex(
          {
            name: 'city',
            value: record2.city,
          },
          undefined,
          undefined,
          undefined,
          'DESC'
        );
        t.match(sortedRecordsDesc, [record2, record1], 'records are sorted in DESC order');
      }
    });

    tap.test('getCount(): ' + dbType, async (t) => {
      if (dbEngine !== 'sql' && dbEngine !== 'mongo' && dbEngine !== 'planetscale') {
        console.log(`skipping getCount test for ${dbEngine}`);
        return;
      }
      const count = await connectionStore.getCount();
      t.equal(count, records.length);
      const countByIndex = await connectionStore.getCount({ name: 'name', value: record1.name });
      t.equal(countByIndex, 1);
    });

    tap.test('delete(): ' + dbType, async (t) => {
      await connectionStore.delete(record1.id);

      const ret0 = await connectionStore.getByIndex({
        name: 'city',
        value: record1.city,
      });

      t.same(ret0.data, [record2], 'unable to get index "city" after delete');

      await connectionStore.delete(record2.id);
      await connectionStore.delete(record3.id);

      const ret1 = await connectionStore.get(record1.id);
      const ret2 = await connectionStore.get(record2.id);

      const ret3 = await connectionStore.getByIndex({
        name: 'name',
        value: record1.name,
      });
      const ret4 = await connectionStore.getByIndex({
        name: 'city',
        value: record1.city,
      });

      t.same(ret1, null, 'delete for record1 failed');
      t.same(ret2, null, 'delete for record2 failed');

      t.same(ret3.data, [], 'delete for record1 failed');
      t.same(ret4.data, [], 'delete for record2 failed');
    });

    tap.test('ttl put(): ' + dbType, async () => {
      await ttlStore.put(record1.id, record1);

      await ttlStore.put(record2.id, record2);
    });

    tap.test('ttl get(): ' + dbType, async (t) => {
      const ret1 = await ttlStore.get(record1.id);
      const ret2 = await ttlStore.get(record2.id);

      t.same(ret1, record1, 'unable to get record1');
      t.same(ret2, record2, 'unable to get record2');
    });

    tap.test('ttl expiry: ' + dbType, async (t) => {
      // mongo runs ttl task every 60 seconds
      if (dbEngine.startsWith('mongo')) {
        return;
      }

      await new Promise((resolve) => setTimeout(resolve, (2 * ttl + 0.5) * 1000));

      const ret1 = await ttlStore.get(record1.id);
      const ret2 = await ttlStore.get(record2.id);

      t.same(ret1, null, 'ttl for record1 failed');
      t.same(ret2, null, 'ttl for record2 failed');
    });

    tap.test('getAll() with TTL: ' + dbType, async (t) => {
      // mongo runs ttl task every 60 seconds
      if (dbEngine.startsWith('mongo') || dbEngine == 'dynamodb') {
        return;
      }

      const testMessage = 'should return no records';
      // getAll without pagination params
      t.same((await ttlStore.getAll()).data, [], `without pagination params ` + testMessage);
      // getAll with pagination params
      t.same((await ttlStore.getAll(0, 2)).data, [], `with pagination params ` + testMessage);
      // getAll with pageLimit set to 0
      t.same((await ttlStore.getAll(0, 0)).data, [], `with pageLimit set to 0 ` + testMessage);
      // getAll with pageLimit > options.pageLimit
      t.same((await ttlStore.getAll(0, 3)).data, [], `with pageLimit > options.pageLimit ` + testMessage);
    });

    tap.test('deleteMany(): ' + dbType, async (t) => {
      await connectionStore.put(
        record1.id,
        record1,
        {
          name: 'city',
          value: record1.city,
        },
        {
          name: 'name',
          value: record1.name,
        }
      );

      await connectionStore.put(
        record2.id,
        record2,
        {
          name: 'city',
          value: record2.city,
        },
        {
          name: 'name',
          value: record2.name,
        }
      );

      await connectionStore.deleteMany([record1.id, record2.id]);

      const ret1 = await connectionStore.get(record1.id);
      const ret2 = await connectionStore.get(record2.id);

      t.same(ret1, null);
      t.same(ret2, null);

      const ret3 = await connectionStore.getByIndex({
        name: 'name',
        value: record1.name,
      });

      const ret4 = await connectionStore.getByIndex({
        name: 'city',
        value: record1.city,
      });

      t.same(ret3.data, []);
      t.same(ret4.data, []);
    });
  }

  tap.test('close():', async () => {
    for (const [, value] of Object.entries(dbObjs)) {
      await value.close();
    }
  });
});
