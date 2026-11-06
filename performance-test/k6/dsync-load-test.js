import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics
export const errorCount = new Counter('errors');

// Load test options
export const options = {
  discardResponseBodies: false,
  thresholds: {
    // http_req_duration: ['p(95)<500'], // 95% of requests should complete in under 500ms
    errors: ['count<1'], // Fewer than 10 errors allowed
  },
  scenarios: {
    load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 45 },
        { duration: '40s', target: 55 },
        { duration: '20s', target: 0 },
      ],
    },
  },
};

const BASE_URL = 'http://localhost:5225';
const API_V1 = `${BASE_URL}/api/v1`;

const manageHeaders = {
  Authorization: 'Api-Key secret',
  'Content-Type': 'application/json',
};

const tenant = `tenant-${randomString(8)}`;
const product = `product-${randomString(8)}`;

const _cache = {};

function generateDSyncSetupLinkPayload() {
  const name = `DSyncSetUpLink-${randomString(8)}-${tenant}-${product}`;
  const expiryDays = Math.floor(Math.random() * 2) + 1;
  const webhook_url = `http://localhost:5225/api/${randomString(5)}`;
  const webhook_secret = randomString(5);

  return {
    tenant,
    product,
    name,
    expiryDays,
    webhook_url,
    webhook_secret,
  };
}

function generateDirectoryPayload() {
  return {
    webhook_url: `http://example.com/webhook-${randomString(8)}`,
    webhook_secret: randomString(12),
    tenant,
    product,
    name: `Directory-${randomString(5)}`,
    type: 'okta-scim-v2',
  };
}

export default async function loadTest() {
  createDSyncSetupLink();
  getDSyncSetupLink();
  getDSyncSetupLinkByProduct();
  deleteDSyncSetupLink();
  createDirectory();
  getDirectoryByTenantAndProduct();
  getDirectoryById();
  getDirectoryByProduct();
  updateDirectory();
  deleteDirectory();

  sleep(1);
}

//Setup Links | Directory Sync

function createDSyncSetupLink() {
  const payload = generateDSyncSetupLinkPayload();

  const response = http.post(`${API_V1}/dsync/setuplinks`, JSON.stringify(payload), {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'createDSyncSetupLink Response status is 201': (r) => r.status === 201,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `DSyncSetUpLink creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

function getDSyncSetupLink() {
  console.log(`GET Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = http.get(`${API_V1}/dsync/setuplinks?tenant=${tenant}&product=${product}`, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'getDSyncSetupLink Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`GET request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

function getDSyncSetupLinkByProduct() {
  console.log(`GET Request Params - Product: ${product}`);

  const response = http.get(`${API_V1}/dsync/setuplinks/product?product=${product}`, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'getDSyncLinkByProduct Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`GET request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

function deleteDSyncSetupLink() {
  console.log(`DELETE Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = http.del(`${API_V1}/dsync/setuplinks?tenant=${tenant}&product=${product}`, null, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'deleteDSyncSetupLink Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`DELETE request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

//Directory Sync

function createDirectory() {
  const payload = generateDirectoryPayload();

  const response = http.post(`${API_V1}/dsync`, JSON.stringify(payload), {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'CreateDirectory Response status is 201': (r) => r.status === 201,
  });

  const result = response.json();

  // Check if result and data are defined before accessing id
  if (result && result.data && result.data.id) {
    _cache.directoryId = result.data.id;
  } else {
    console.error('Directory ID not found in response:', JSON.stringify(result));
  }

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `Directory creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

function getDirectoryByTenantAndProduct() {
  console.log(`GET Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = http.get(`${API_V1}/dsync?tenant=${tenant}&product=${product}`, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'getDirectoryByTenantAndProduct Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`GET request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

function getDirectoryById() {
  const { directoryId } = _cache; // Retrieve directory ID from context

  if (!directoryId) {
    console.error('Directory ID not found for this VU.');
    return;
  }

  const response = http.get(`${API_V1}/dsync/${directoryId}`, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'getDirectoryById Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `GET request failed for Directory ID: ${directoryId}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  } else {
    console.log(`Directory successfully retrieved by ID: ${directoryId}`);
  }
}

function getDirectoryByProduct() {
  const response = http.get(`${API_V1}/dsync/product?product=${product}`, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'getDirectoryByProduct Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `GET request failed for Product: ${product}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  } else {
    console.log(`Directory successfully retrieved by Product: ${product}`);
  }
}

function updateDirectory() {
  const { directoryId } = _cache;

  if (!directoryId) {
    console.error('Directory ID not found for this VU.');
    return;
  }

  const updatedDirectoryName = `Directory-${randomString(10)}`;

  const payload = JSON.stringify({
    name: updatedDirectoryName,
  });

  const response = http.patch(`${API_V1}/dsync/${directoryId}`, payload, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'updateDirectoryName Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`Directory name successfully updated to: ${updatedDirectoryName}`);
  } else {
    errorCount.add(1);
    console.error(
      `PATCH request failed for Directory ID: ${directoryId}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

function deleteDirectory() {
  const { directoryId } = _cache;

  if (!directoryId) {
    console.error('Directory ID not found for this VU.');
    return;
  }

  const response = http.del(`${API_V1}/dsync/${directoryId}`, null, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'deleteDirectory Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`Directory successfully deleted. ID: ${directoryId}`);
  } else {
    errorCount.add(1);
    console.error(
      `DELETE request failed for Directory ID: ${directoryId}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}
