import { Entity, Column, Index } from 'typeorm';

@Entity({ name: 'jackson_ttl' })
export class JacksonTTL {
  @Column({
    primary: true,
    type: 'varchar',
    length: 250,
  })
  key!: string;

  @Index('_jackson_ttl_expires_at')
  @Column({
    type: 'bigint',
  })
  expiresAt!: number;
}
