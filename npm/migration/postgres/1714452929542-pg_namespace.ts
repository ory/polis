import { MigrationInterface, QueryRunner } from "typeorm";

export class PgNamespace1714452929542 implements MigrationInterface {
    name = 'PgNamespace1714452929542'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "jackson_store" ALTER COLUMN "namespace" TYPE VARCHAR(256)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "jackson_store" ALTER COLUMN "namespace" TYPE VARCHAR(64)`);
    }

}
