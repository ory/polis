import { test, expect } from '@playwright/test';
import {
  createConnection,
  getConnection,
  deleteConnection,
  getRawMetadata,
  newConnection,
  expectedConnection,
  getConnectionByProduct,
} from '../../helpers/sso';
import { options } from '../../helpers/api';

test.use(options);

test.afterEach(async ({ request }) => {
  const { tenant, product } = newConnection;

  // Delete the connection after each test
  await deleteConnection(request, { tenant, product });
});

test.describe('POST /api/v1/sso', () => {
  test('should be able to create a SSO Connection', async ({ request }) => {
    const response = await createConnection(request, newConnection);

    expect(response).toMatchObject(expectedConnection);
  });

  test('should not be able to create a SSO Connection if params are invalid', async ({ request }) => {
    const testCases = [
      {
        data: {
          ...newConnection,
          tenant: null,
        },
        expectedError: 'Please provide tenant',
      },
      {
        data: {
          ...newConnection,
          product: null,
        },
        expectedError: 'Please provide product',
      },
      {
        data: {
          ...newConnection,
          defaultRedirectUrl: null,
        },
        expectedError: 'Please provide a defaultRedirectUrl',
      },
      {
        data: {
          ...newConnection,
          redirectUrl: null,
        },
        expectedError: 'Please provide redirectUrl',
      },
      {
        data: {
          ...newConnection,
          rawMetadata: null,
          metadataUrl: null,
        },
        expectedError: 'Please provide rawMetadata or encodedRawMetadata or metadataUrl',
      },
    ];

    for (const testCase of testCases) {
      const response = await request.post('/api/v1/sso', {
        data: testCase.data,
      });

      expect(response.ok()).toBe(false);
      expect(response.status()).toBe(400);
      expect(await response.json()).toMatchObject({
        error: { message: testCase.expectedError },
      });
    }
  });

  test('should be able to create multiple SSO Connections for same tenant & product', async ({ request }) => {
    const { tenant, product } = newConnection;

    // Create the first connection
    await createConnection(request, newConnection);

    // Create the second connection
    await createConnection(request, {
      ...newConnection,
      rawMetadata: getRawMetadata('https://saml.example.com/entityid-1'),
    });

    // Fetch the connections
    const response = await getConnection(request, { tenant, product });

    expect(response).toHaveLength(2);
    expect(response[0]).toMatchObject({
      ...expectedConnection,
      idpMetadata: {
        entityID: 'https://saml.example.com/entityid-1',
      },
    });
    expect(response[1]).toMatchObject(expectedConnection);
  });
});

test.describe('GET /api/v1/sso', () => {
  const { tenant, product } = newConnection;

  test('should be able to get SSO Connections', async ({ request }) => {
    await createConnection(request, newConnection);

    const response = await getConnection(request, { tenant, product });

    expect(response).toMatchObject([expectedConnection]);
  });

  // TODO: Add test for invalid tenant and product
});

test.describe('PATCH /api/v1/sso', () => {
  const { tenant, product } = newConnection;

  test('should be able to update a SSO Connection', async ({ request }) => {
    await createConnection(request, newConnection);

    const connection = await getConnection(request, { tenant, product });

    // Update the connection
    const response = await request.patch('/api/v1/sso', {
      data: {
        tenant,
        product,
        clientID: connection[0].clientID,
        clientSecret: connection[0].clientSecret,
        name: 'new connection name',
        description: 'new connection description',
        defaultRedirectUrl: 'http://localhost:3366/login/saml-new',
        redirectUrl: 'http://localhost:3366/new/*',
        metadataUrl: 'https://mocksaml.com/api/saml/metadata',
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(204);

    // Fetch the connection again to check if the update was successful
    const updatedConnection = await getConnection(request, { tenant, product });

    expect(updatedConnection).toMatchObject([
      {
        name: 'new connection name',
        description: 'new connection description',
        defaultRedirectUrl: 'http://localhost:3366/login/saml-new',
        redirectUrl: ['http://localhost:3366/new/*'],
      },
    ]);
  });

  // TODO: Add test for invalid tenant and product
  // TODO: Add test for invalid clientID and clientSecret
});

test.describe('DELETE /api/v1/sso', () => {
  const { tenant, product } = newConnection;

  test('should be able to delete a SSO Connection', async ({ request }) => {
    await createConnection(request, newConnection);

    // Delete the connection
    await deleteConnection(request, { tenant, product });

    // Fetch the connection again to check if the delete was successful
    const connection = await getConnection(request, { tenant, product });

    expect(connection).toMatchObject([]);
  });
});

test.describe('GET /api/v1/sso/exists', () => {
  const { tenant, product } = newConnection;

  test('should be able to check if a connection exists', async ({ request }) => {
    await createConnection(request, newConnection);

    // Fetch a connection that exists
    let response = await request.get('/api/v1/sso/exists', {
      params: {
        tenant,
        product,
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(204);

    // Fetch a connection that does not exist
    response = await request.get('/api/v1/sso/exists', {
      params: {
        tenant: 'boxyhq',
        product: 'saml-jackson',
      },
    });

    expect(response.ok()).toBe(false);
    expect(response.status()).toBe(404);
  });
});

test.describe('GET /api/v1/sso/product', () => {
  const { product } = newConnection;

  test('should get empty array for SSO connection by product', async ({ request }) => {
    const response = await getConnectionByProduct(request, product);

    expect(response).toMatchObject([]);
    expect(response.length).toBe(0);
  });

  test('should be able to get SSO Connections by product', async ({ request }) => {
    await createConnection(request, newConnection);

    const response = await getConnectionByProduct(request, product);

    expect(response).toMatchObject([expectedConnection]);
    expect(response.length).toBe(1);
  });
});
