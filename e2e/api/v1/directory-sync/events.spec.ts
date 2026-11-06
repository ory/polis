import { test, expect } from '@playwright/test';
import {
  createDirectory,
  deleteDirectory,
  directoryPayload,
  getDirectory,
  getDirectoryEvents,
  updateDirectory,
} from '../../helpers/directories';
import groups from '@boxyhq/saml-jackson/test/dsync/data/groups';
import { addGroupMember, createGroup } from '../../helpers/groups';
import { options } from '../../helpers/api';

test.use(options);

const { tenant, product } = { ...directoryPayload, tenant: 'api-boxyhq-3' };
const memberId = 'member1';

test.beforeAll(async ({ request, baseURL }) => {
  let directory = await createDirectory(request, {
    ...directoryPayload,
    webhook_url: `${baseURL}/api/hello`,
    webhook_secret: 'secret',
    tenant,
  });

  directory = await updateDirectory(request, directory, {
    log_webhook_events: true,
  });

  const group = await createGroup(request, directory, groups[0]);
  await addGroupMember(request, directory, group, memberId);
});

test.afterAll(async ({ request }) => {
  const [directory] = await getDirectory(request, { tenant, product });

  await deleteDirectory(request, directory.id);
});

test.describe('GET /api/v1/dsync/events', () => {
  test('should be able to get list of events from a directory', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });

    // Get events using tenant, product & directoryId
    const data = await getDirectoryEvents(request, { tenant, product, directoryId: directory.id });

    expect(data.length).toBe(2);
  });
});

test.describe('GET /api/v1/dsync/events/:event', () => {
  test('should be able to get event', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });

    // Get events using directoryId
    const events = await getDirectoryEvents(request, {
      directoryId: directory.id,
    });

    const response = await request.get(`/api/v1/dsync/events/${events[0].id}`, {
      params: {
        tenant,
        product,
        directoryId: directory.id,
      },
    });

    const { data: event } = await response.json();

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(event.status_code).toBe(200);
  });
});

test.describe('DELETE /api/v1/dsync/events', () => {
  test('should be able to delete all the events from directory', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });

    const response = await request.delete(`/api/v1/dsync/events`, {
      params: {
        directoryId: directory.id,
      },
    });

    const events = await getDirectoryEvents(request, {
      tenant,
      product,
      directoryId: directory.id,
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(events.length).toBe(0);
  });
});
