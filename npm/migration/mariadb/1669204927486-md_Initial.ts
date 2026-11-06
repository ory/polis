import { MigrationInterface, QueryRunner } from "typeorm";

export class mdInitial1669204927486 implements MigrationInterface {
    name = 'mdInitial1669204927486'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE \`jackson_store\` (\`key\` varchar(250) NOT NULL, \`value\` text NOT NULL, \`iv\` varchar(64) NULL, \`tag\` varchar(64) NULL, \`createdAt\` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP(), \`modifiedAt\` timestamp NULL, PRIMARY KEY (\`key\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`jackson_ttl\` (\`key\` varchar(250) NOT NULL, \`expiresAt\` bigint NOT NULL, INDEX \`_jackson_ttl_expires_at\` (\`expiresAt\`), PRIMARY KEY (\`key\`)) ENGINE=InnoDB`);
        await queryRunner.query(`CREATE TABLE \`jackson_index\` (\`id\` int NOT NULL AUTO_INCREMENT, \`key\` varchar(250) NOT NULL, \`storeKey\` varchar(250) NOT NULL, INDEX \`_jackson_index_key\` (\`key\`), INDEX \`_jackson_index_key_store\` (\`key\`, \`storeKey\`), PRIMARY KEY (\`id\`)) ENGINE=InnoDB`);
        await queryRunner.query(`ALTER TABLE \`jackson_index\` ADD CONSTRAINT \`FK_937b040fb2592b4671cbde09e83\` FOREIGN KEY (\`storeKey\`) REFERENCES \`jackson_store\`(\`key\`) ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE \`jackson_index\` DROP FOREIGN KEY \`FK_937b040fb2592b4671cbde09e83\``);
        await queryRunner.query(`DROP INDEX \`_jackson_index_key_store\` ON \`jackson_index\``);
        await queryRunner.query(`DROP INDEX \`_jackson_index_key\` ON \`jackson_index\``);
        await queryRunner.query(`DROP TABLE \`jackson_index\``);
        await queryRunner.query(`DROP INDEX \`_jackson_ttl_expires_at\` ON \`jackson_ttl\``);
        await queryRunner.query(`DROP TABLE \`jackson_ttl\``);
        await queryRunner.query(`DROP TABLE \`jackson_store\``);
    }

}
