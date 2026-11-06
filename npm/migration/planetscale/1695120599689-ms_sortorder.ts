import { MigrationInterface, QueryRunner } from "typeorm";

export class MsSortorder1695120599689 implements MigrationInterface {
    name = 'MsSortorder1695120599689'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` CHANGE \`createdAt\` \`createdAt\` timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)`);
        await queryRunner.query(`ALTER TABLE \`jackson_store\` CHANGE \`modifiedAt\` \`modifiedAt\` timestamp(6) NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_store\` CHANGE \`modifiedAt\` \`modifiedAt\` timestamp(0) NULL`);
        await queryRunner.query(`ALTER TABLE \`jackson_store\` CHANGE \`createdAt\` \`createdAt\` timestamp(0) NOT NULL DEFAULT CURRENT_TIMESTAMP`);
    }

}
