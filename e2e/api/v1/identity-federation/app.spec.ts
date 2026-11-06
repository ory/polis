import { test, expect } from '@playwright/test';
import { IdentityFederationApp } from '@boxyhq/saml-jackson';
import { options } from '../../helpers/api';

test.use(options);

const expectedApp = {
  name: 'Test App',
  tenant: 'api-boxyhq',
  product: 'api-saml-jackson',
  id: expect.any(String),
  entityId: 'https://boxyhq.com/entity-id',
  acsUrl: 'https://boxyhq.com/acs',
};
const expectedApp1 = {
  name: 'Test App1',
  tenant: 'api-boxyhq-1',
  product: 'api-saml-jackson-1',
  id: expect.any(String),
  entityId: 'https://boxyhq.com/entity-id-1',
  acsUrl: 'https://boxyhq.com/acs-1',
};
const newUrlPath = 'identity-federation';
const oldUrlPath = 'federated-saml';

let app = {} as IdentityFederationApp;
let app1 = {} as IdentityFederationApp;

const beforeAll = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? expectedApp : expectedApp1;
  const response = await request.post(`/api/v1/${urlPath}`, {
    data: {
      ...currApp,
    },
  });

  const localApp = (await response.json()).data;

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(201);

  return localApp;
};

test.beforeAll(async ({ request }) => {
  app = await beforeAll(oldUrlPath, request);
  app1 = await beforeAll(newUrlPath, request);
});

const testGETById = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? app : app1;
  const response = await request.get(`/api/v1/${urlPath}?id=${currApp?.id}`);

  const { data } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(data).toMatchObject(currApp);
};

const testGETByTenantProduct = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? app : app1;
  const response = await request.get(
    `/api/v1/${urlPath}?tenant=${currApp?.tenant}&product=${currApp?.product}`
  );

  const { data } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(data).toMatchObject(currApp);
};

const testGETByProduct = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? app : app1;
  const response = await request.get(`/api/v1/${urlPath}/product?product=${currApp?.product}`);

  const { data } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(data).toMatchObject([currApp]);
};

test.describe('GET /api/v1/identity-federation', () => {
  test('Fetch app by id', async ({ request }) => {
    await testGETById(oldUrlPath, request);
    await testGETById(newUrlPath, request);
  });

  test('Fetch app by tenant and product', async ({ request }) => {
    await testGETByTenantProduct(oldUrlPath, request);
    await testGETByTenantProduct(newUrlPath, request);
  });

  test('Fetch app by product', async ({ request }) => {
    await testGETByProduct(oldUrlPath, request);
    await testGETByProduct(newUrlPath, request);
  });
});

const testPATCHById = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? app : app1;
  const response = await request.patch(`/api/v1/${urlPath}`, {
    data: {
      id: currApp?.id,
      name: 'Updated App',
    },
  });

  const { data } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(data).toMatchObject({
    ...currApp,
    name: 'Updated App',
  });
};

const testPATCHByTenantProduct = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? app : app1;
  const response = await request.patch(`/api/v1/${urlPath}`, {
    data: {
      tenant: currApp?.tenant,
      product: currApp?.product,
      name: 'Updated App 2',
    },
  });

  const { data } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(data).toMatchObject({
    ...currApp,
    name: 'Updated App 2',
  });
};

test.describe('PATCH /api/v1/identity-federation', () => {
  test('Update app by id', async ({ request }) => {
    await testPATCHById(oldUrlPath, request);
    await testPATCHById(newUrlPath, request);
  });

  test('Update app by tenant and product', async ({ request }) => {
    await testPATCHByTenantProduct(oldUrlPath, request);
    await testPATCHByTenantProduct(newUrlPath, request);
  });
});

const testDELETEById = async (urlPath, request) => {
  const currApp = urlPath === oldUrlPath ? app : app1;
  const response = await request.delete(`/api/v1/${urlPath}?id=${currApp?.id}`);

  const { data } = await response.json();

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
  expect(data).toMatchObject({});

  // Confirm app is deleted
  const response2 = await request.get(`/api/v1/${urlPath}?id=${currApp?.id}`);

  expect(response2.ok()).toBe(false);
  expect(response2.status()).toBe(404);
};

test.describe('DELETE /api/v1/identity-federation', () => {
  test('Delete app by id', async ({ request }) => {
    await testDELETEById(oldUrlPath, request);
    await testDELETEById(newUrlPath, request);
  });
});
