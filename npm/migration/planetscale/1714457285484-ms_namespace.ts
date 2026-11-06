import { MigrationInterface, QueryRunner } from "typeorm";

export class MsNamespace1714457285484 implements MigrationInterface {
    name = 'MsNamespace1714457285484'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` MODIFY \`namespace\` varchar(256) NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` MODIFY \`namespace\` varchar(64) NULL`);
    }

}
