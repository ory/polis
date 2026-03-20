require('reflect-metadata');
import { DataSource, DatabaseType, DataSourceOptions } from 'typeorm';
import * as mssql from './src/db/sql/mssql';

const type =
  process.env.DB_ENGINE === 'planetscale'
    ? 'mysql'
    : <DatabaseType>process.env.DB_TYPE || <DatabaseType>'postgres';

let entitiesDir;
if (process.env.DB_ENGINE === 'planetscale') {
  entitiesDir = 'planetscale';
} else {
  switch (type) {
    case 'mssql':
    case 'sqlite':
      entitiesDir = `sql/${type}`;
      break;
    case 'mariadb':
    case 'mysql':
      entitiesDir = `sql/mariadb`;
      break;
    default:
      entitiesDir = 'sql';
      break;
  }
}
const migrationsDir = process.env.DB_ENGINE === 'planetscale' ? 'planetscale' : type;

let ssl;
if (process.env.DB_SSL === 'true') {
  ssl = {
    rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false',
  };
}

const url =
  process.env.DB_URL || process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/postgres';

let AppDataSource: DataSource;

const baseOpts = {
  type,
  synchronize: false,
  migrationsTableName: '_jackson_migrations',
  logging: 'all',
  entities: [`src/db/${entitiesDir}/entity/**/*.ts`],
  migrations:
    type === 'mssql' || type === 'sqlite' || type === 'cockroachdb'
      ? [`migration/${migrationsDir}/**/*.ts`]
      : [`migration/${migrationsDir}/**/*.ts`, `migration/sql/**/*.ts`],
};

if (type === 'mssql') {
  const mssqlOpts = mssql.parseURL(url);
  AppDataSource = new DataSource(<DataSourceOptions>{
    host: mssqlOpts.host,
    port: mssqlOpts.port,
    database: mssqlOpts.database,
    username: mssqlOpts.username,
    password: mssqlOpts.password,
    options: mssqlOpts.options,
    ...baseOpts,
  });
} else if (type === 'sqlite') {
  AppDataSource = new DataSource(<DataSourceOptions>{
    database: url,
    ...baseOpts,
    type: 'better-sqlite3',
  });
} else {
  AppDataSource = new DataSource(<DataSourceOptions>{
    url:
      process.env.DB_URL ||
      process.env.DATABASE_URL ||
      'postgresql://postgres:postgres@localhost:5432/postgres',
    ssl,
    ...baseOpts,
  });
}

export default AppDataSource;
