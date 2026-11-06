import { MigrationInterface, QueryRunner } from "typeorm";

export class PgInitial1733850225778 implements MigrationInterface {
    name = 'PgInitial1733850225778'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "jackson_store" ("key" varchar(1500) NOT NULL, "value" string NOT NULL, "iv" varchar(64), "tag" varchar(64), "createdAt" timestamp NOT NULL DEFAULT current_timestamp(), "modifiedAt" timestamp, "namespace" varchar(256), CONSTRAINT "PK_87b6fc1475fbd1228d2f53c6f4a" PRIMARY KEY ("key"))`);
        await queryRunner.query(`CREATE INDEX "_jackson_store_namespace" ON "jackson_store" ("namespace") `);
        await queryRunner.query(`CREATE TABLE "jackson_ttl" ("key" varchar(1500) NOT NULL, "expiresAt" int8 NOT NULL, CONSTRAINT "PK_7c9bcdfb4d82e873e19935ec806" PRIMARY KEY ("key"))`);
        await queryRunner.query(`CREATE INDEX "_jackson_ttl_expires_at" ON "jackson_ttl" ("expiresAt") `);
        await queryRunner.query(`CREATE SEQUENCE "jackson_index_id_seq"`);
        await queryRunner.query(`CREATE TABLE "jackson_index" ("id" INT DEFAULT nextval('"jackson_index_id_seq"') NOT NULL, "key" varchar(1500) NOT NULL, "storeKey" varchar(1500) NOT NULL, CONSTRAINT "PK_a95aa83f01e3c73e126856b7820" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key" ON "jackson_index" ("key") `);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key_store" ON "jackson_index" ("key", "storeKey") `);
        await queryRunner.query(`CREATE INDEX "IDX_937b040fb2592b4671cbde09e8" ON "jackson_index" ("storeKey") `);
        await queryRunner.query(`ALTER TABLE "jackson_index" ADD CONSTRAINT "FK_937b040fb2592b4671cbde09e83" FOREIGN KEY ("storeKey") REFERENCES "jackson_store"("key") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "jackson_index" DROP CONSTRAINT "FK_937b040fb2592b4671cbde09e83"`);
        await queryRunner.query(`DROP INDEX "jackson_index"@"IDX_937b040fb2592b4671cbde09e8" CASCADE`);
        await queryRunner.query(`DROP INDEX "jackson_index"@"_jackson_index_key_store" CASCADE`);
        await queryRunner.query(`DROP INDEX "jackson_index"@"_jackson_index_key" CASCADE`);
        await queryRunner.query(`DROP TABLE "jackson_index"`);
        await queryRunner.query(`DROP SEQUENCE "jackson_index_id_seq"`);
        await queryRunner.query(`DROP INDEX "jackson_ttl"@"_jackson_ttl_expires_at" CASCADE`);
        await queryRunner.query(`DROP TABLE "jackson_ttl"`);
        await queryRunner.query(`DROP INDEX "jackson_store"@"_jackson_store_namespace" CASCADE`);
        await queryRunner.query(`DROP TABLE "jackson_store"`);
    }

}
