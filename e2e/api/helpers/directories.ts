import { expect, type APIRequestContext } from '@playwright/test';
import { Directory } from 'npm/src';

const directoryBase = {
  tenant: 'api-boxyhq',
  product: 'api-saml-jackson',
  name: 'Directory name',
  type: 'okta-scim-v2',
};

export const directoryPayload = {
  ...directoryBase,
  webhook_url: '',
  webhook_secret: '',
};

export const directoryExpected = {
  ...directoryBase,
  id: expect.any(String),
  log_webhook_events: false,
  scim: {
    path: expect.any(String),
    secret: expect.any(String),
    endpoint: expect.any(String),
  },
  webhook: { endpoint: '', secret: '' },
};

export const updateDirectory = async (request: APIRequestContext, directory: Directory, data: any) => {
  const response = await request.patch(`/api/v1/dsync/${directory.id}`, {
    data,
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  const { data: updatedDirectory } = await response.json();
  return updatedDirectory;
};

export const createDirectory = async (request: APIRequestContext, payload: typeof directoryPayload) => {
  const response = await request.post('/api/v1/dsync', {
    data: {
      ...payload,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(201);

  const { data } = await response.json();

  return data;
};

export const getDirectory = async (
  request: APIRequestContext,
  { tenant, product }: { tenant: string; product: string }
) => {
  const response = await request.get('/api/v1/dsync', {
    params: {
      tenant,
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  const { data } = await response.json();

  return data;
};

export const getDirectoryByProduct = async (request: APIRequestContext, { product }: { product: string }) => {
  const response = await request.get('/api/v1/dsync/product', {
    params: {
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  const { data } = await response.json();

  return data;
};

export const deleteDirectory = async (request: APIRequestContext, directoryId: string) => {
  const response = await request.delete(`/api/v1/dsync/${directoryId}`);

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
};

export const getDirectoryEvents = async (
  request: APIRequestContext,
  params: {
    tenant?: string;
    product?: string;
    directoryId: string;
  }
) => {
  const response = await request.get(`/api/v1/dsync/events`, {
    params,
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  const { data } = await response.json();
  return data;
};
