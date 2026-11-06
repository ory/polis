import { test, expect } from '@playwright/test';
import { createDirectory, deleteDirectory, directoryPayload, getDirectory } from '../../helpers/directories';
import groups from '@boxyhq/saml-jackson/test/dsync/data/groups';
import { createGroup } from '../../helpers/groups';
import { options } from '../../helpers/api';

test.use(options);

const { tenant, product } = { ...directoryPayload, tenant: 'api-boxyhq-3' };

test.beforeAll(async ({ request }) => {
  const directory = await createDirectory(request, {
    ...directoryPayload,
    tenant,
  });

  await createGroup(request, directory, groups[0]);
  await createGroup(request, directory, groups[1]);
});

test.afterAll(async ({ request }) => {
  const [directory] = await getDirectory(request, { tenant, product });

  await deleteDirectory(request, directory.id);
});

test.describe('GET /api/v1/dsync/groups', () => {
  test('should be able to get all groups from a directory', async ({ request }) => {
    const response = await request.get('/api/v1/dsync/groups', {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryGroups } = await response.json();

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(directoryGroups.length).toBe(2);
  });
});

test.describe('GET /api/v1/dsync/groups/:id', () => {
  test('should be able to get a group from a directory', async ({ request }) => {
    let response = await request.get('/api/v1/dsync/groups', {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryGroups } = await response.json();
    const [firstGroup] = directoryGroups;

    response = await request.get(`/api/v1/dsync/groups/${firstGroup.id}`, {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryGroup } = await response.json();

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(directoryGroup).toMatchObject(firstGroup);
  });
});
