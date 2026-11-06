import tap from 'tap';
import sinon from 'sinon';

import users from '../data/users';
import requests from '../data/user-requests';
import { jacksonOptions } from '../../utils';
import { IDirectorySyncController, Directory } from '../../../src/typings';
import { createAxiosInstance } from '../../../src/event/axios';

const axiosInstance = createAxiosInstance(console);

let directorySync: IDirectorySyncController;

const directory1Payload = {
  tenant: 'boxyhq-1',
  product: 'saml-jackson',
  type: 'okta-scim-v2' as Directory['type'],
  webhook_url: 'https://example.com/webhook-1',
  webhook_secret: 'secret',
};

const directory2Payload = {
  tenant: 'boxyhq-2',
  product: 'saml-jackson',
  type: 'okta-scim-v2' as Directory['type'],
  webhook_url: 'https://example.com/webhook-2',
  webhook_secret: 'secret',
};

const webhookBatchSize = 2;

tap.before(async () => {
  const options = {
    ...jacksonOptions,
    dsync: {
      webhookBatchSize,
    },
  };

  const jackson = await (await import('../../../src/index')).default(options);

  directorySync = jackson.directorySyncController;

  const { data: directory1 } = await directorySync.directories.create({
    ...directory1Payload,
  });

  const { data: directory2 } = await directorySync.directories.create({
    ...directory2Payload,
  });

  if (!directory1 || !directory2) {
    throw new Error('Failed to create directories');
  }

  // Enable logging for directory 1
  await directorySync.directories.update(directory1.id, {
    log_webhook_events: true,
  });

  // Add some users to generate events
  await directorySync.requests.handle(requests.create(directory1, users[0]));
  await directorySync.requests.handle(requests.create(directory1, users[1]));
  await directorySync.requests.handle(requests.create(directory2, users[1]));
  await directorySync.requests.handle(requests.create(directory2, users[0]));
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('Event batching', async (t) => {
  t.test('Should be able to fetch the events in batches', async (t) => {
    // Take the first batch of events
    let events = await directorySync.events.batch.fetchNextBatch(0, webhookBatchSize);

    t.equal(events.length, 2);

    for (const event of events) {
      t.equal(event.status, 'PENDING');
      t.equal(event.retry_count, 0);
      t.equal(event.event.event, 'user.created');
    }

    t.equal(events[0].event.tenant, 'boxyhq-1');
    t.equal(events[1].event.tenant, 'boxyhq-1');

    // Take the second batch of events
    events = await directorySync.events.batch.fetchNextBatch(2, webhookBatchSize);

    t.equal(events.length, 2);

    for (const event of events) {
      t.equal(event.status, 'PENDING');
      t.equal(event.retry_count, 0);
      t.equal(event.event.event, 'user.created');
    }

    t.equal(events[0].event.tenant, 'boxyhq-2');
    t.equal(events[1].event.tenant, 'boxyhq-2');

    // Take the third batch of events
    events = await directorySync.events.batch.fetchNextBatch(4, webhookBatchSize);

    t.equal(events.length, 0);
  });

  t.test('Should be able to process the events', async (t) => {
    let events = await directorySync.events.batch.fetchNextBatch(0, webhookBatchSize);

    const sandbox = sinon.createSandbox();
    const axiosPostStub = sandbox.stub(axiosInstance, 'post').resolves({ status: 200 });

    await directorySync.events.batch.process();

    t.equal(axiosPostStub.callCount, 2);

    const expectedPayloadForDirectory1 = events
      .filter((event) => event.event.tenant === 'boxyhq-1')
      .map((event) => event.event);

    const expectedPayloadForDirectory2 = events
      .filter((event) => event.event.tenant === 'boxyhq-2')
      .map((event) => event.event);

    // First call
    t.equal(axiosPostStub.firstCall.args[0], directory1Payload.webhook_url);
    t.equal((axiosPostStub.firstCall.args[1] as any[]).length, 2);
    t.hasStrict(axiosPostStub.firstCall.args[1], expectedPayloadForDirectory1);

    // Second call
    t.equal(axiosPostStub.secondCall.args[0], directory2Payload.webhook_url);
    t.equal((axiosPostStub.secondCall.args[1] as any[]).length, 2);
    t.hasStrict(axiosPostStub.secondCall.args[1], expectedPayloadForDirectory2);

    sandbox.restore();

    // Now that the events have been processed, they should be deleted
    events = await directorySync.events.batch.fetchNextBatch(0, webhookBatchSize);

    t.equal(events.length, 0);
  });

  t.test('Should log the webhook events if logging is enabled', async (t) => {
    const { data: logs } = await directorySync.webhookLogs
      .setTenantAndProduct(directory1Payload.tenant, directory1Payload.product)
      .getAll();

    t.ok(logs);
    t.equal(logs.length, 1);
    t.equal(logs[0].status_code, 200);
    t.equal(logs[0].delivered, true);
    t.equal(logs[0].webhook_endpoint, directory1Payload.webhook_url);
    t.equal(Array.isArray(logs[0].payload), true);

    if (Array.isArray(logs[0].payload)) {
      t.match(logs[0].payload.length, 2);
    }
  });

  t.test('Should not log the webhook events if logging is disabled', async (t) => {
    const { data: logs } = await directorySync.webhookLogs
      .setTenantAndProduct(directory2Payload.tenant, directory2Payload.product)
      .getAll();

    t.ok(logs);
    t.equal(logs.length, 0);
  });
});
