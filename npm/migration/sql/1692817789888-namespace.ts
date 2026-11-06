import { MigrationInterface, QueryRunner } from "typeorm"

export class namespace1692817789888 implements MigrationInterface {
  name = 'namespace1692817789888'

  public async up(queryRunner: QueryRunner): Promise<void> {
    const response = await queryRunner.query("select jackson.key from jackson_store jackson")
      const searchTerm = ':';
      for (const k in response) {
        const key = response[k].key;
        const tokens2 = key.split(searchTerm).slice(0, 2);
        const value = tokens2.join(searchTerm);
        queryRunner.query(`update jackson_store set namespace = '${value}' where jackson_store.key = '${key}'`)
      }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
      const response = await queryRunner.query("select jackson.key from jackson_store jackson")
        for (const k in response) {
          const key = response[k].key;
          queryRunner.query(`update jackson_store set namespace = NULL where jackson_store.key = '${key}'`)
        }
  }
  
}
