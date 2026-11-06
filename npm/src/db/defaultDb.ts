import { JacksonOption } from '../typings';

export default function defaultDb(opts: JacksonOption) {
  opts.db = opts.db || {};
  opts.db.manualMigration = opts.db.manualMigration || false;
  opts.db.ttl = (opts.db.ttl || 300) * 1; // TTL for the code, session and token stores (in seconds)
  opts.db.cleanupLimit = (opts.db.cleanupLimit || 1000) * 1; // Limit cleanup of TTL entries to this many items at a time
  if ('driver' in opts.db) {
    return opts;
  }

  opts.db.engine = opts.db.engine || 'sql';
  opts.db.url = opts.db.url || 'postgresql://postgres:postgres@localhost:5432/postgres';
  opts.db.type = opts.db.type || 'postgres'; // Only needed if DB_ENGINE is sql.
  opts.db.dynamodb = opts.db.dynamodb || {};
  opts.db.dynamodb.region = opts.db.dynamodb.region || 'us-east-1';
  opts.db.dynamodb.readCapacityUnits = opts.db.dynamodb.readCapacityUnits || 5;
  opts.db.dynamodb.writeCapacityUnits = opts.db.dynamodb.writeCapacityUnits || 5;

  return opts;
}
