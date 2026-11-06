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
//SAML Federation App

function generateSAMLFederationAppPayload() {
  return {
    acsUrl: `https://iam.twilio.com/v1/Accounts/ACxxxxxxxxxxxxxx${randomString(8)}`,
    entityId: `https://ory.sh/entity-id/${randomString(5)}`,
    redirectUrl: `http://localhost:3366`,
    type: 'saml',
    tenant,
    product,
    name: `id-fed-app-${randomString(5)}`,
  };
}

async function createSAMLFederationApp() {
  const payload = generateSAMLFederationAppPayload();

  const response = await http.asyncRequest('POST', `${API_V1}/identity-federation`, JSON.stringify(payload), {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'createSAMLFederationApp Response status is 201': (r) => r.status === 201,
  });

  const result = response.json();

  if (result && result.data && result.data.id) {
    _cache.samlFederationAppId = result.data.id;
  } else {
    console.error('SAMLFederationApp ID not found in response:', JSON.stringify(result));
  }

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `SAMLFederationApp creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function updateSAMLFederationApp() {
  const { samlFederationAppId } = _cache;

  const updatedSAMLFederationAppName = `id-fed-app-${randomString(4)}`;

  const payload = JSON.stringify({
    name: updatedSAMLFederationAppName,
    id: samlFederationAppId,
  });

  const response = await http.asyncRequest('PATCH', `${API_V1}/identity-federation`, payload, {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'updateSAMLFederationApp Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`SAMLFederationApp name successfully updated to: ${updatedSAMLFederationAppName}`);
  } else {
    errorCount.add(1);
    console.error(
      `PATCH request failed for SAMLFederationApp ID: ${samlFederationAppId}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function getSAMLFederationApp() {
  const { samlFederationAppId } = _cache;

  const response = await http.asyncRequest(
    'GET',
    `${API_V1}/identity-federation/?id=${samlFederationAppId}`,
    null,
    {
      headers: manageHeaders,
    }
  );

  const isSuccessful = check(response, {
    'getSAMLFederationApp Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `GET request failed for SAMLFederationApp ID: ${samlFederationAppId}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  } else {
    console.log(`SAMLFederationApp successfully retrieved by ID: ${samlFederationAppId}`);
  }
}

async function getSAMLFederationAppByProduct() {
  const response = await http.asyncRequest(
    'GET',
    `${API_V1}/identity-federation/product?product=${product}`,
    null,
    {
      headers: manageHeaders,
    }
  );

  const isSuccessful = check(response, {
    'getSAMLFederationAppByProduct Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `GET request failed for Product: ${product}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  } else {
    console.log(`SAMLFederationAppByProduct successfully retrieved by Product: ${product}`);
  }
}

async function deleteSAMLFederationApp() {
  const { samlFederationAppId } = _cache;

  const response = await http.asyncRequest(
    'DELETE',
    `${API_V1}/identity-federation/?id=${samlFederationAppId}`,
    null,
    {
      headers: manageHeaders,
    }
  );

  const isSuccessful = check(response, {
    'deleteSAMLFederationApp Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`SAMLFederationApp successfully deleted. ID: ${samlFederationAppId}`);
  } else {
    errorCount.add(1);
    console.error(
      `DELETE request failed for deleteSAMLFederationApp ID: ${samlFederationAppId}. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

export default async function loadTest() {
  await createSAMLFederationApp();
  await getSAMLFederationApp();
  await updateSAMLFederationApp();
  await getSAMLFederationAppByProduct();
  await deleteSAMLFederationApp();
  sleep(1);
}
