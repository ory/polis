import { MigrationInterface, QueryRunner } from "typeorm";

export class MdNamespace1714417013715 implements MigrationInterface {
    name = 'MdNamespace1714417013715'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` MODIFY \`namespace\` varchar(256) NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` MODIFY \`namespace\` varchar(64) NULL`);
    }

}
