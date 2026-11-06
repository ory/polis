import { MigrationInterface, QueryRunner } from "typeorm";

export class msNamespace1692767993709 implements MigrationInterface {
    name = 'msNamespace1692767993709'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` ADD \`namespace\` varchar(64) NULL`);
        await queryRunner.query(`CREATE INDEX \`_jackson_store_namespace\` ON \`jackson_store\` (\`namespace\`)`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX \`_jackson_store_namespace\` ON \`jackson_store\``);
        await queryRunner.query(`ALTER TABLE \`jackson_store\` DROP COLUMN \`namespace\``);
    }

}
