import tap from 'tap';
import { resolveWebhookLogsTTL, webhookLogsTTL } from '../../src/directory-sync/utils';
import { WebhookEventsLogger } from '../../src/directory-sync/scim/WebhookEventsLogger';

tap.test('resolveWebhookLogsTTL', async (t) => {
  t.equal(resolveWebhookLogsTTL(undefined), webhookLogsTTL, 'unset returns the 7-day default');
  t.equal(resolveWebhookLogsTTL(''), 0, 'empty string returns 0 (indefinite)');
  t.equal(resolveWebhookLogsTTL('   '), 0, 'whitespace-only returns 0 (indefinite)');
  t.equal(resolveWebhookLogsTTL('720h'), 2592000, '720h (30 days) returns 2592000 seconds');
  t.equal(resolveWebhookLogsTTL('30d'), 2592000, '30d returns 2592000 seconds');
  t.equal(resolveWebhookLogsTTL('168h'), webhookLogsTTL, '168h equals the 7-day default');
  t.equal(
    resolveWebhookLogsTTL('1d garbage'),
    86400,
    'a string with a valid token is parsed leniently (trailing text ignored)'
  );

  const warnings: string[] = [];
  const logger = { warn: (msg: string) => warnings.push(msg) };
  t.equal(
    resolveWebhookLogsTTL('not-a-duration', logger),
    webhookLogsTTL,
    'an unparseable value falls back to the default'
  );
  t.equal(warnings.length, 1, 'an unparseable value logs exactly one warning');
});

tap.test('WebhookEventsLogger uses the configured TTL when storing logs', async (t) => {
  const storeCalls: Array<{ namespace: string; ttl?: number }> = [];
  const fakeStore = {
    put: async () => undefined,
  };
  const fakeDb = {
    store: (namespace: string, ttl?: number) => {
      storeCalls.push({ namespace, ttl });
      return fakeStore as any;
    },
  };

  const directory = {
    id: 'dir-1',
    webhook: { endpoint: 'https://example.com', secret: 'secret' },
  } as any;
  const event = { event: 'user.created' } as any;

  // Use a distinctive non-default TTL so a regression that drops the value is
  // caught (db.store defaults ttl to 0, so asserting on 0 would not).
  const logger = new WebhookEventsLogger({ db: fakeDb as any, ttlSeconds: 4242 });
  logger.setTenantAndProduct('tenant-1', 'product-1');
  await logger.log(directory, event, 200);

  t.equal(storeCalls.length, 1, 'the store is opened exactly once');
  t.equal(storeCalls[0].ttl, 4242, 'the store is opened with the configured TTL');
  t.match(storeCalls[0].namespace, /:tenant-1:product-1$/, 'the namespace is scoped to tenant and product');
});
