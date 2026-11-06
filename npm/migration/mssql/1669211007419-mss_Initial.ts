import { MigrationInterface, QueryRunner } from "typeorm";

export class mssInitial1669211007419 implements MigrationInterface {
    name = 'mssInitial1669211007419'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "jackson_store" ("key" varchar(250) NOT NULL, "value" text NOT NULL, "iv" varchar(64), "tag" varchar(64), "createdAt" datetime NOT NULL CONSTRAINT "DF_49022ed8c543adefc99ff762200" DEFAULT getdate(), "modifiedAt" datetime, CONSTRAINT "PK_87b6fc1475fbd1228d2f53c6f4a" PRIMARY KEY ("key"))`);
        await queryRunner.query(`CREATE TABLE "jackson_index" ("id" int NOT NULL IDENTITY(1,1), "key" varchar(250) NOT NULL, "storeKey" varchar(250) NOT NULL, CONSTRAINT "PK_a95aa83f01e3c73e126856b7820" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key" ON "jackson_index" ("key") `);
        await queryRunner.query(`CREATE INDEX "_jackson_index_key_store" ON "jackson_index" ("key", "storeKey") `);
        await queryRunner.query(`CREATE TABLE "jackson_ttl" ("key" varchar(250) NOT NULL, "expiresAt" bigint NOT NULL, CONSTRAINT "PK_7c9bcdfb4d82e873e19935ec806" PRIMARY KEY ("key"))`);
        await queryRunner.query(`CREATE INDEX "_jackson_ttl_expires_at" ON "jackson_ttl" ("expiresAt") `);
        await queryRunner.query(`ALTER TABLE "jackson_index" ADD CONSTRAINT "FK_937b040fb2592b4671cbde09e83" FOREIGN KEY ("storeKey") REFERENCES "jackson_store"("key") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "jackson_index" DROP CONSTRAINT "FK_937b040fb2592b4671cbde09e83"`);
        await queryRunner.query(`DROP INDEX "_jackson_ttl_expires_at" ON "jackson_ttl"`);
        await queryRunner.query(`DROP TABLE "jackson_ttl"`);
        await queryRunner.query(`DROP INDEX "_jackson_index_key_store" ON "jackson_index"`);
        await queryRunner.query(`DROP INDEX "_jackson_index_key" ON "jackson_index"`);
        await queryRunner.query(`DROP TABLE "jackson_index"`);
        await queryRunner.query(`DROP TABLE "jackson_store"`);
    }

}
