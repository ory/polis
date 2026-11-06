import { test, expect } from '@playwright/test';
import {
  createConnection,
  deleteConnection,
  newConnection,
  deleteSSOTraces,
  getSSOTracesByProduct,
  getSSOTraceById,
  countSSOTracesByProduct,
} from '../../helpers/sso';
import { options } from '../../helpers/api';
import { oauthAuthorize } from '../../helpers/oauth';

test.use(options);

test.beforeEach(async ({ request }) => {
  await createConnection(request, newConnection);
});

test.afterEach(async ({ request }) => {
  const { tenant, product } = newConnection;

  // Delete the connection & traces after each test
  await deleteConnection(request, { tenant, product });
  await deleteSSOTraces(request, product);
});

test.describe('GET /api/v1/sso-traces/product', () => {
  test('should be able to get empty list of traces', async ({ request }) => {
    const list = await getSSOTracesByProduct(request, newConnection.product);

    expect(list.data.length).toBe(0);
  });
});

test.describe('GET /api/v1/sso-traces/product/count', () => {
  test('should be able to get non empty list of traces', async ({ request }) => {
    await oauthAuthorize(
      request,
      {
        client_id: 'dummy',
        tenant: 'dummy',
        product: newConnection.product,
        state: 'Bb-w_AqDxZh90BBVz4PRhtRIRetOgo0AR0pmrhzyICU',
        response_type: 'code',
        redirect_uri: newConnection.redirectUrl[0].replaceAll('*', ''),
        code_challenge: 'OcMni5eZvSrQ2ev7tPICbcE7q1piL8Abi8IfJtWbUtY',
        code_challenge_method: 'S256',
      },
      true
    );

    const res = await countSSOTracesByProduct(request, newConnection.product);

    expect(res.count).toBeGreaterThan(0);
  });
});

test.describe('GET /api/v1/sso-traces', () => {
  test('should be able to get sso trace by Id', async ({ request }) => {
    await oauthAuthorize(
      request,
      {
        client_id: 'dummy',
        tenant: 'dummy',
        product: newConnection.product,
        state: 'Bb-w_AqDxZh90BBVz4PRhtRIRetOgo0AR0pmrhzyICU',
        response_type: 'code',
        redirect_uri: newConnection.redirectUrl[0].replaceAll('*', ''),
        code_challenge: 'OcMni5eZvSrQ2ev7tPICbcE7q1piL8Abi8IfJtWbUtY',
        code_challenge_method: 'S256',
      },
      true
    );

    const list = await getSSOTracesByProduct(request, newConnection.product);
    expect(list.data.length).toBe(1);

    const trace = await getSSOTraceById(request, list.data[0].traceId);
    expect(trace.data).toMatchObject(list.data[0]);
  });
});

test.describe('DELETE /api/v1/sso-traces/product', () => {
  test('should be able to delete sso trace by product', async ({ request }) => {
    await oauthAuthorize(
      request,
      {
        client_id: 'dummy',
        tenant: 'dummy',
        product: newConnection.product,
        state: 'Bb-w_AqDxZh90BBVz4PRhtRIRetOgo0AR0pmrhzyICU',
        response_type: 'code',
        redirect_uri: newConnection.redirectUrl[0].replaceAll('*', ''),
        code_challenge: 'OcMni5eZvSrQ2ev7tPICbcE7q1piL8Abi8IfJtWbUtY',
        code_challenge_method: 'S256',
      },
      true
    );

    let res = await countSSOTracesByProduct(request, newConnection.product);
    expect(res.count).toBeGreaterThan(0);

    await deleteSSOTraces(request, newConnection.product);

    res = await countSSOTracesByProduct(request, newConnection.product);
    expect(res.count).toBe(0);
  });
});
