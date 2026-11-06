import { test, expect } from '@playwright/test';
import {
  createDirectory,
  deleteDirectory,
  directoryExpected,
  directoryPayload,
  getDirectory,
  getDirectoryByProduct,
} from '../../helpers/directories';
import { options } from '../../helpers/api';

test.use(options);

const { tenant, product } = directoryPayload;

test.beforeAll(async ({ request }) => {
  const directory = await createDirectory(request, directoryPayload);

  expect(directory).toMatchObject(directoryExpected);
});

test.afterAll(async ({ request }) => {
  const [directory] = await getDirectory(request, { tenant, product });

  if (!directory) {
    return;
  }
  await deleteDirectory(request, directory.id);
});

test.describe('POST /api/v1/dsync', () => {
  test('should not be able to create a directory if params are invalid', async ({ request }) => {
    const testCases = [
      {
        data: {
          ...directoryPayload,
          tenant: '',
        },
        expectedError: 'Missing required parameters.',
      },
      {
        data: {
          ...directoryPayload,
          product: '',
        },
        expectedError: 'Missing required parameters.',
      },
    ];

    for (const testCase of testCases) {
      const response = await request.post('/api/v1/dsync', {
        data: testCase.data,
      });

      expect(response.ok()).toBe(false);
      expect(response.status()).toBe(400);
      expect(await response.json()).toMatchObject({
        error: { message: testCase.expectedError },
      });
    }
  });
});

test.describe('GET /api/v1/dsync', () => {
  test('should be able to get a directory by tenant and product', async ({ request }) => {
    const directory = await getDirectory(request, { tenant, product });

    expect(directory).toMatchObject([directoryExpected]);
  });

  test('should be able to get a directory by ID', async ({ request }) => {
    const directory = await getDirectory(request, { tenant, product });

    const response = await request.get(`/api/v1/dsync/${directory[0].id}`);

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({ data: directoryExpected });
  });
});

test.describe('PATCH /api/v1/dsync/{directoryId}', () => {
  test('should be able update', async ({ request, baseURL }) => {
    const directories = await getDirectory(request, { tenant, product });
    const directory = directories[0];

    // Update name
    let response = await request.patch(`/api/v1/dsync/${directory.id}`, {
      data: {
        name: 'new name',
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      data: {
        ...directoryExpected,
        name: 'new name',
      },
    });

    // Deactivate directory
    response = await request.patch(`/api/v1/dsync/${directory.id}`, {
      data: {
        deactivated: true,
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      data: {
        ...directoryExpected,
        name: 'new name',
        deactivated: true,
      },
    });

    // Update webhook
    response = await request.patch(`/api/v1/dsync/${directory.id}`, {
      data: {
        webhook_url: `${baseURL}/api/hello`,
        webhook_secret: 'new-secret',
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      data: {
        ...directoryExpected,
        name: 'new name',
        deactivated: true,
        webhook: {
          endpoint: `${baseURL}/api/hello`,
          secret: 'new-secret',
        },
      },
    });

    // Fetch directory again
    response = await request.get(`/api/v1/dsync/${directory.id}`);

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      data: {
        ...directoryExpected,
        name: 'new name',
        deactivated: true,
        webhook: {
          endpoint: `${baseURL}/api/hello`,
          secret: 'new-secret',
        },
      },
    });
  });
});

test.describe('GET /api/v1/dsync/product', () => {
  test('should be able to get a directory by product', async ({ request }) => {
    let directories = await getDirectoryByProduct(request, { product });
    expect(directories.length).toBe(1);

    await deleteDirectory(request, directories[0].id);

    directories = await getDirectoryByProduct(request, { product });
    expect(directories.length).toBe(0);
  });
});
