import { MigrationInterface, QueryRunner } from "typeorm";

export class MssNamespace1714421718208 implements MigrationInterface {
    name = 'MssNamespace1714421718208'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "jackson_store" ALTER COLUMN "namespace" varchar(256)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "jackson_store" ALTER COLUMN "namespace" varchar(64)`);
    }

}
