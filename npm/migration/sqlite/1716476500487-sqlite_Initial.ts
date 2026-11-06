import { MigrationInterface, QueryRunner } from "typeorm";

export class SqliteInitial1716476500487 implements MigrationInterface {
    name = 'SqliteInitial1716476500487'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "jackson_ttl" ("key" varchar(250) PRIMARY KEY NOT NULL, "expiresAt" bigint NOT NULL)`);
        await queryRunner.query(`CREATE INDEX "_jackson_ttl_expires_at" ON "jackson_ttl" ("expiresAt") `);
        await queryRunner.query(`CREATE TABLE "jackson_store" ("key" varchar(1500) PRIMARY KEY NOT NULL, "value" text NOT NULL, "iv" varchar(64), "tag" varchar(64), "createdAt" datetime NOT NULL DEFAULT ((STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))), "modifiedAt" datetime, "namespace" varchar(256))`);
        await queryRunner.query(`CREATE INDEX "_jackson_store_namespace" ON "jackson_store" ("namespace") `);
        await queryRunner.query(`CREATE TABLE "jackson_index" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "key" varchar(250) NOT NULL, "storeKey" varchar(250) NOT NULL)`);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key" ON "jackson_index" ("key") `);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key_store" ON "jackson_index" ("key", "storeKey") `);
        await queryRunner.query(`DROP INDEX "_jackson_index_key"`);
        await queryRunner.query(`DROP INDEX "_jackson_index_key_store"`);
        await queryRunner.query(`CREATE TABLE "temporary_jackson_index" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "key" varchar(250) NOT NULL, "storeKey" varchar(250) NOT NULL, CONSTRAINT "FK_937b040fb2592b4671cbde09e83" FOREIGN KEY ("storeKey") REFERENCES "jackson_store" ("key") ON DELETE CASCADE ON UPDATE NO ACTION)`);
        await queryRunner.query(`INSERT INTO "temporary_jackson_index"("id", "key", "storeKey") SELECT "id", "key", "storeKey" FROM "jackson_index"`);
        await queryRunner.query(`DROP TABLE "jackson_index"`);
        await queryRunner.query(`ALTER TABLE "temporary_jackson_index" RENAME TO "jackson_index"`);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key" ON "jackson_index" ("key") `);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key_store" ON "jackson_index" ("key", "storeKey") `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "_jackson_index_key_store"`);
        await queryRunner.query(`DROP INDEX "_jackson_index_key"`);
        await queryRunner.query(`ALTER TABLE "jackson_index" RENAME TO "temporary_jackson_index"`);
        await queryRunner.query(`CREATE TABLE "jackson_index" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "key" varchar(250) NOT NULL, "storeKey" varchar(250) NOT NULL)`);
        await queryRunner.query(`INSERT INTO "jackson_index"("id", "key", "storeKey") SELECT "id", "key", "storeKey" FROM "temporary_jackson_index"`);
        await queryRunner.query(`DROP TABLE "temporary_jackson_index"`);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key_store" ON "jackson_index" ("key", "storeKey") `);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key" ON "jackson_index" ("key") `);
        await queryRunner.query(`DROP INDEX "_jackson_index_key_store"`);
        await queryRunner.query(`DROP INDEX "_jackson_index_key"`);
        await queryRunner.query(`DROP TABLE "jackson_index"`);
        await queryRunner.query(`DROP INDEX "_jackson_store_namespace"`);
        await queryRunner.query(`DROP TABLE "jackson_store"`);
        await queryRunner.query(`DROP INDEX "_jackson_ttl_expires_at"`);
        await queryRunner.query(`DROP TABLE "jackson_ttl"`);
    }

}
