import { test, expect } from '@playwright/test';
import { options } from '../../helpers/api';

const tenant = 'tenant-1';
const product = 'product-1';

test.use(options);

// POST /api/v1/dsync/setuplinks
test('create the setup link', async ({ request }) => {
  const response = await request.post('/api/v1/dsync/setuplinks', {
    data: {
      tenant,
      product,
      webhook_url: 'http://localhost:3000/webhook',
      webhook_secret: 'webhook-secret',
    },
  });

  const setupLink = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(201);
  expect(setupLink.data.tenant).toMatch(tenant);
  expect(setupLink.data.product).toMatch(product);
  expect(setupLink.data.service).toMatch('dsync');
});

// GET /api/v1/dsync/setuplinks?id={id}
test('get the setup link by id', async ({ request }) => {
  let response = await request.get('/api/v1/dsync/setuplinks', {
    params: {
      tenant,
      product,
    },
  });

  const { data: setupLink } = await response.json();

  response = await request.get('/api/v1/dsync/setuplinks', {
    params: {
      id: setupLink.setupID,
    },
  });

  const fetchedSetupLink = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(fetchedSetupLink.data.tenant).toMatch(tenant);
  expect(fetchedSetupLink.data.product).toMatch(product);
  expect(fetchedSetupLink.data.service).toMatch('dsync');
});

// GET /api/v1/dsync/setuplinks?tenant={tenant}&product={product}
test('get the setup link by tenant & product', async ({ request }) => {
  const response = await request.get('/api/v1/dsync/setuplinks', {
    params: {
      tenant,
      product,
    },
  });

  const setupLink = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(setupLink.data.tenant).toMatch(tenant);
  expect(setupLink.data.product).toMatch(product);
  expect(setupLink.data.service).toMatch('dsync');
});

// DELETE /api/v1/dsync/setuplinks?tenant={tenant}&product={product}
test('delete the setup link by tenant & product', async ({ request }) => {
  let response = await request.delete('/api/v1/dsync/setuplinks', {
    params: {
      tenant,
      product,
    },
  });

  await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  response = await request.get('/api/v1/dsync/setuplinks', {
    params: {
      tenant,
      product,
    },
  });

  expect(response.ok()).toBe(false);
  expect(response.status()).toBe(404);
});

// DELETE /api/v1/dsync/setuplinks?id={id}
test('delete the setup link by id', async ({ request }) => {
  let response = await request.post('/api/v1/dsync/setuplinks', {
    data: {
      tenant,
      product,
      webhook_url: 'http://localhost:3000/webhook',
      webhook_secret: 'webhook-secret',
    },
  });

  const { data: setupLink } = await response.json();

  response = await request.delete('/api/v1/dsync/setuplinks', {
    params: {
      id: setupLink.setupID,
    },
  });

  await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  response = await request.get('/api/v1/dsync/setuplinks', {
    params: {
      id: setupLink.setupID,
    },
  });

  expect(response.ok()).toBe(false);
  expect(response.status()).toBe(404);
});

// GET /api/v1/dsync/setuplinks/product
test('get the setup links by product', async ({ request }) => {
  // Create 2 setup links
  await request.post('/api/v1/dsync/setuplinks', {
    data: {
      tenant: 'tenant-2',
      product,
      webhook_url: 'http://localhost:3000/webhook',
      webhook_secret: 'webhook-secret',
    },
  });

  await request.post('/api/v1/dsync/setuplinks', {
    data: {
      tenant: 'tenant-3',
      product,
      webhook_url: 'http://localhost:3000/webhook',
      webhook_secret: 'webhook-secret',
    },
  });

  const response = await request.get('/api/v1/dsync/setuplinks/product', {
    params: {
      product,
    },
  });

  const { data: setupLinks } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(setupLinks.length).toBe(2);
  expect(setupLinks[0].product).toBe(product);
  expect(setupLinks[1].product).toBe(product);

  await request.delete('/api/v1/dsync/setuplinks', {
    params: {
      tenant: 'tenant-2',
      product,
    },
  });

  await request.delete('/api/v1/dsync/setuplinks', {
    params: {
      tenant: 'tenant-3',
      product,
    },
  });
});
