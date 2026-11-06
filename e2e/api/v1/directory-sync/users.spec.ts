import { test, expect } from '@playwright/test';
import users from '../../../../npm/test/dsync/data/users';
import { createDirectory, deleteDirectory, directoryPayload, getDirectory } from '../../helpers/directories';
import { createUser } from '../../helpers/users';
import { options } from '../../helpers/api';

test.use(options);

const { tenant, product } = { ...directoryPayload, tenant: 'api-boxyhq-4' };

test.beforeAll(async ({ request }) => {
  const directory = await createDirectory(request, {
    ...directoryPayload,
    tenant,
  });

  await createUser(request, directory, users[0]);
  await createUser(request, directory, users[1]);
});

test.afterAll(async ({ request }) => {
  const [directory] = await getDirectory(request, { tenant, product });

  await deleteDirectory(request, directory.id);
});

test.describe('GET /api/v1/dsync/users', () => {
  test('should be able to get all users from a directory', async ({ request }) => {
    const response = await request.get('/api/v1/dsync/users', {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryUsers } = await response.json();

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(directoryUsers.length).toBe(2);
  });
});

test.describe('GET /api/v1/dsync/users/:id', () => {
  test('should be able to get a user from a directory', async ({ request }) => {
    let response = await request.get('/api/v1/dsync/users', {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryUsers } = await response.json();
    const [firstUser] = directoryUsers;

    response = await request.get(`/api/v1/dsync/users/${firstUser.id}`, {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryUser } = await response.json();

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(directoryUser).toMatchObject(firstUser);
  });
});
