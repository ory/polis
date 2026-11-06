import http from 'k6/http';
import { check, sleep } from 'k6';
import exec from 'k6/execution';
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

function generateSSOPayload(rawMetadata) {
  const defaultRedirectUrl = `http://localhost:3366/login/saml`;
  const redirectUrl = [`http://localhost:3366/*`];
  const name = `SSOConnection-${randomString(5)}-${tenant}-${product}`;
  const description = `SSOConnection Description - ${randomString(10)}`;
  const namespace = `${tenant}-${product}`;
  const metadataUrl = `https://mocksaml.com/api/namespace/${namespace}/saml/metadata`;

  const _payload = {
    tenant,
    product,
    defaultRedirectUrl,
    redirectUrl,
    name,
    description,
  };

  if (rawMetadata) {
    _payload.rawMetadata = rawMetadata;
  } else {
    _payload.metadataUrl = metadataUrl;
  }
  return _payload;
}

function generateUpdateSSOPayload() {
  const { clientID, clientSecret, metadataUrl } = _cache;

  const defaultRedirectUrl = `http://localhost:3366/login/saml`;
  const redirectUrl = [`http://localhost:3366/*`];
  const name = `SSOConnection-${randomString(8)}-${tenant}-${product}`;
  const description = `SSOConnection Description - ${randomString(11)}`;

  return {
    tenant,
    product,
    clientID,
    clientSecret,
    defaultRedirectUrl,
    redirectUrl,
    name,
    description,
    metadataUrl,
  };
}

function generateSetupLinkPayload() {
  const redirectUrl = ['http://localhost:3000'];
  const defaultRedirectUrl = 'http://localhost:3000/default';

  return {
    tenant,
    product,
    redirectUrl,
    defaultRedirectUrl,
  };
}

export async function setup() {
  await createSSOConnectionViaRawMetadata();
}

export async function teardown() {
  await http.asyncRequest('DELETE', `${API_V1}/sso?product=${product}&tenant=${tenant}`, null, {
    headers: { Authorization: manageHeaders['Authorization'] },
  });
}

export default async function loadTest() {
  await createSSOConnection();
  await getSSOConnection();
  await updateSSOConnection();
  await getSSOConnectionByProduct();
  await deleteSSOConnection();
  await createSetupLink();
  await getSetupLink();
  await deleteSetupLink();
  // benchmark SAML response path
  await processSAMLResponse();
  sleep(1);
}

//Single Sign On

async function createSSOConnection() {
  const payload = generateSSOPayload();

  const response = await http.asyncRequest('POST', `${API_V1}/sso`, JSON.stringify(payload), {
    headers: manageHeaders,
    tags: {
      sso: 'create',
    },
  });

  const isSuccessful = check(response, {
    'createSSOConnection Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);

    _cache.clientID = responseData.clientID;
    _cache.clientSecret = responseData.clientSecret;
    _cache.metadataUrl = responseData.metadataUrl;

    console.log(
      `SSO Connection created successfully for tenant: ${responseData.tenant}, product: ${responseData.product}`
    );
  } else {
    errorCount.add(1);
    console.error(
      `SSO Connection creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function updateSSOConnection() {
  const { clientID, clientSecret, metadataUrl } = _cache;

  if (!tenant || !product || !clientID || !clientSecret || !metadataUrl) {
    console.error('Missing context data for SSO Connection update.');
    return;
  }

  const payload = generateUpdateSSOPayload();

  const response = await http.asyncRequest('PATCH', `${API_V1}/sso`, JSON.stringify(payload), {
    headers: manageHeaders,
    tags: {
      sso: 'update',
    },
  });

  const isSuccessful = check(response, {
    'updateSSOConnection Response status is 204': (r) => r.status === 204,
  });

  if (isSuccessful) {
    console.log(`SSO Connection successfully updated for tenant: ${tenant}, product: ${product}`);
  } else {
    errorCount.add(1);
    console.error(
      `SSO Connection update failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function getSSOConnection() {
  // const { tenant, product } = _cache;
  console.log(`GET Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = await http.asyncRequest('GET', `${API_V1}/sso?tenant=${tenant}&product=${product}`, null, {
    headers: manageHeaders,
    tags: {
      sso: 'get',
    },
  });

  const isSuccessful = check(response, {
    'getSSOConnection Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`GET request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function getSSOConnectionByProduct() {
  const { clientID } = _cache;
  console.log(`GET Request Params - Product: ${product}, ClientID: ${clientID}`);

  const response = await http.asyncRequest(
    'GET',
    `${API_V1}/sso?product=${product}&clientID=${clientID}`,
    null,
    {
      headers: manageHeaders,
      tags: {
        sso: 'getByProduct',
      },
    }
  );

  const isSuccessful = check(response, {
    'getSSOConnectionByProduct Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`GET request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function deleteSSOConnection() {
  console.log(`DELETE Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = await http.asyncRequest(
    'DELETE',
    `${API_V1}/sso?product=${product}&tenant=${tenant}`,
    null,
    {
      headers: { Authorization: manageHeaders['Authorization'] },
      tags: {
        sso: 'delete',
      },
    }
  );

  const isSuccessful = check(response, {
    'deleteSSOConnection Response status is 204': (r) => r.status === 204,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`DELETE request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
    exec.test.abort(`DELETE failed`);
  }
}

//Setup Links | Single Sign On

async function createSetupLink() {
  const payload = generateSetupLinkPayload();

  const response = await http.asyncRequest('POST', `${API_V1}/sso/setuplinks`, JSON.stringify(payload), {
    headers: manageHeaders,
    tags: {
      sso: 'create_setup_link',
    },
  });

  const isSuccessful = check(response, {
    'createSetupLink Response status is 201': (r) => r.status === 201,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `SetUpLink creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function getSetupLink() {
  console.log(`GET Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = await http.asyncRequest(
    'GET',
    `${API_V1}/sso/setuplinks?tenant=${tenant}&product=${product}`,
    null,
    {
      headers: manageHeaders,
      tags: {
        sso: 'get_setup_link',
      },
    }
  );

  const isSuccessful = check(response, {
    'getSetUpLink Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`GET request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function deleteSetupLink() {
  console.log(`DELETE Request Params - Tenant: ${tenant}, Product: ${product}`);

  const response = await http.asyncRequest(
    'DELETE',
    `${API_V1}/sso/setuplinks?product=${product}&tenant=${tenant}`,
    null,
    {
      headers: manageHeaders,
      tags: {
        sso: 'delete_setup_link',
      },
    }
  );

  const isSuccessful = check(response, {
    'deleteSetUpLink Response status is 200': (r) => r.status === 200,
  });

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(`DELETE request failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function createSSOConnectionViaRawMetadata() {
  let rawMetadata = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://saml.example.com/entityid" validUntil="2035-01-21T12:25:53.458Z">
<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing">
<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:X509Data>
<ds:X509Certificate>MIIDXTCCAkWgAwIBAgIURk/J0oQyqlZeAeYl5Rx1L/f8chwwDQYJKoZIhvcNAQEL BQAwPTELMAkGA1UEBhMCSU4xDzANBgNVBAgMBktlcmFsYTEOMAwGA1UEBwwFS29j aGkxDTALBgNVBAoMBEJveHkwIBcNMjQxMTE4MTYxNDE3WhgPMzAyNDAzMjExNjE0 MTdaMD0xCzAJBgNVBAYTAklOMQ8wDQYDVQQIDAZLZXJhbGExDjAMBgNVBAcMBUtv Y2hpMQ0wCwYDVQQKDARCb3h5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC AQEAqI5BkqWZMRfaGsMADicTXG6KFX826nVHnavv4D5VtVsVvmArGRkIZwWjiLd3 Isrd4v2NYDaF1gf10VOrltGJVMfXvq3GdEg+/gBa+qWE8nOBfAaHrCdeQFJZh7rT 8LRtlcVOGLgapxanQA4qIWIlydeUXEuvNl0KECHGH8qXT/pi0+q8OW6GalQKAAEn fRIGAfRZUWLQzmgqQdFTDcsm9IHoFBtOavSNUoNGUxqcKA4WqlzeiuTdsemttWbu F+xZU8YEcnaO8CbrUzJo7mEVofTJYi3Ovoj6p6wHy0dNrtnbXX6Xku9fPNtyG+vV zAueYGtqJ8FfefqZpgHO/TYjEwIDAQABo1MwUTAdBgNVHQ4EFgQUYJ0ofqzwfnQ3 +0S1LOjBV/mw70IwHwYDVR0jBBgwFoAUYJ0ofqzwfnQ3+0S1LOjBV/mw70IwDwYD VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAnr60pDYRkkJeFn/+mgiq KAIjOvDQ3dsw5If/4sAlIdkffCvuHbTqbIN55W8Z3d22UKrt3zVGx6pg2GfSUzpJ A/dNyO28wD45J+3sbO0rjst5hIwYmYbTim8imLvnjmIwCCQCMKrZpI7nOVxWYMia OedfIu8ywXxVGLJA+xLzZ3IJpl05wyvwqp7AjrFSAyJ0BryCPPeScHHrx/3ZGqYE t0MbJrRJqJFQfwRBIWsMayfv4jxx7ghDaFik6mu1QpZkq+Aelq0mnxDA6RllwjAX adqI1w5wYHEXD7xqqAnusr5NOCrbuAzwhLuau0zwkr3chfdpUlgyo7KLExLNxove ig==</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</md:KeyDescriptor>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:4000/api/saml/sso"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:4000/api/saml/sso"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>`;

  const payload = generateSSOPayload(rawMetadata);

  const response = await http.asyncRequest('POST', `${API_V1}/sso`, JSON.stringify(payload), {
    headers: manageHeaders,
    tags: {
      sso: 'create_via_raw_metadata',
    },
  });

  const isSuccessful = check(response, {
    'createSSOConnectionViaRawMetadata Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = response.json();

    console.log(
      `SSO Connection created successfully for tenant: ${responseData.tenant}, product: ${responseData.product}`
    );
  } else {
    errorCount.add(1);
    console.error(
      `SSO Connection creation failed Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
    exec.test.abort('createSSOConnectionViaRawMetadata status code was *not* 200');
  }
}

async function processSAMLResponse() {
  const samlResponse =
    'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6UmVzcG9uc2UgRGVzdGluYXRpb249Imh0dHA6Ly9sb2NhbGhvc3Q6NTIyNS9hcGkvb2F1dGgvc2FtbCIgSUQ9Il84NDk4YWZiYWJkZWFjYmZmNmU4YyIgSXNzdWVJbnN0YW50PSIyMDI1LTAxLTIxVDE2OjM4OjI3LjUzN1oiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc2FtbC5leGFtcGxlLmNvbS9lbnRpdHlpZDwvc2FtbDpJc3N1ZXI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIjXzg0OThhZmJhYmRlYWNiZmY2ZThjIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+S2t5Q2FnYUJKZ3E2YXIxOXM3Z3ZIa0Z1eVZNRXkrcmF2cWVqMkpwS2Z4cz08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+ZmUreXJacmg0dHNGeXBnbEZIbDB5SU9mQ0dpd3dLMUU3dVNxQ25WYThCaFhGN0QxQURFcjJOT0xLelpvdytpeGpDWDNyWmZOdGNxWExpYmRPRElrY01CTnFTL0FHakR3RHVKTFlkSmFiRGE0UlYxTUtsRTlZekIxeERsV0pmZWFzckdBQW5YNHdobjZ0c1BQajdudlMvYmN6SU5Ed2ZTaHVRMjF5KzZ5Mm9lSGtMK0lzdlNET1dsZUxyV3FYelFkTG5UaUMxcThyN09DZ1EwME5jaThMYkZNcUZDVzhGZVhRM3hJc0U1U3hWbTUzR1lyU3VhM01Xc1EwNlo3WEE0aW5IUWZlazNRdXVRR2Z6QmEySWorMy9vd3lscXVTbDd1UGFjb2M2RFZHSk04YjBpY0VOdUpvVzZFUkdCeTlKMHU5N2hURkd0K1RiUVBpT0cyWHVBWkt3PT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURYVENDQWtXZ0F3SUJBZ0lVUmsvSjBvUXlxbFplQWVZbDVSeDFML2Y4Y2h3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd1BURUxNQWtHQTFVRUJoTUNTVTR4RHpBTkJnTlZCQWdNQmt0bGNtRnNZVEVPTUF3R0ExVUVCd3dGUzI5agphR2t4RFRBTEJnTlZCQW9NQkVKdmVIa3dJQmNOTWpReE1URTRNVFl4TkRFM1doZ1BNekF5TkRBek1qRXhOakUwCk1UZGFNRDB4Q3pBSkJnTlZCQVlUQWtsT01ROHdEUVlEVlFRSURBWkxaWEpoYkdFeERqQU1CZ05WQkFjTUJVdHYKWTJocE1RMHdDd1lEVlFRS0RBUkNiM2g1TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQwpBUUVBcUk1QmtxV1pNUmZhR3NNQURpY1RYRzZLRlg4MjZuVkhuYXZ2NEQ1VnRWc1Z2bUFyR1JrSVp3V2ppTGQzCklzcmQ0djJOWURhRjFnZjEwVk9ybHRHSlZNZlh2cTNHZEVnKy9nQmErcVdFOG5PQmZBYUhyQ2RlUUZKWmg3clQKOExSdGxjVk9HTGdhcHhhblFBNHFJV0lseWRlVVhFdXZObDBLRUNIR0g4cVhUL3BpMCtxOE9XNkdhbFFLQUFFbgpmUklHQWZSWlVXTFF6bWdxUWRGVERjc205SUhvRkJ0T2F2U05Vb05HVXhxY0tBNFdxbHplaXVUZHNlbXR0V2J1CkYreFpVOFlFY25hTzhDYnJVekpvN21FVm9mVEpZaTNPdm9qNnA2d0h5MGROcnRuYlhYNlhrdTlmUE50eUcrdlYKekF1ZVlHdHFKOEZmZWZxWnBnSE8vVFlqRXdJREFRQUJvMU13VVRBZEJnTlZIUTRFRmdRVVlKMG9mcXp3Zm5RMworMFMxTE9qQlYvbXc3MEl3SHdZRFZSMGpCQmd3Rm9BVVlKMG9mcXp3Zm5RMyswUzFMT2pCVi9tdzcwSXdEd1lEClZSMFRBUUgvQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBbnI2MHBEWVJra0plRm4vK21naXEKS0FJak92RFEzZHN3NUlmLzRzQWxJZGtmZkN2dUhiVHFiSU41NVc4WjNkMjJVS3J0M3pWR3g2cGcyR2ZTVXpwSgpBL2ROeU8yOHdENDVKKzNzYk8wcmpzdDVoSXdZbVliVGltOGltTHZuam1Jd0NDUUNNS3JacEk3bk9WeFdZTWlhCk9lZGZJdTh5d1h4VkdMSkEreEx6WjNJSnBsMDV3eXZ3cXA3QWpyRlNBeUowQnJ5Q1BQZVNjSEhyeC8zWkdxWUUKdDBNYkpyUkpxSkZRZndSQklXc01heWZ2NGp4eDdnaERhRmlrNm11MVFwWmtxK0FlbHEwbW54REE2Umxsd2pBWAphZHFJMXc1d1lIRVhEN3hxcUFudXNyNU5PQ3JidUF6d2hMdWF1MHp3a3IzY2hmZHBVbGd5bzdLTEV4TE54b3ZlCmlnPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbHA6U3RhdHVzIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48c2FtbDpBc3NlcnRpb24gSUQ9Il85ZDQ1YWZkOWUyZWJmNzAwOGQzOSIgSXNzdWVJbnN0YW50PSIyMDI1LTAxLTIxVDE2OjM4OjI3LjUzN1oiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIj48c2FtbDpJc3N1ZXIgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDplbnRpdHkiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc2FtbC5leGFtcGxlLmNvbS9lbnRpdHlpZDwvc2FtbDpJc3N1ZXI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIjXzlkNDVhZmQ5ZTJlYmY3MDA4ZDM5Ij48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+eGJOcGNKZG1UREd6bU8xWmd0WjlLK0Y1RVplaUR0ekViaU8wbCtNMWhkST08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+b1FWWFNVQ0xwVGUxVGs5Y2w5dWh5WGt5UFdLUW1KbWhkWS9ucFZUSG1XT1F5cVhpTUpTYmRvaUNUQWZkUy81T2JBTkVMeFE5Qy8zQXViTVMyNW5aTWZSK1cxWXREcWgwL1A2QU1QcmNiK0NyWG1ZTFMxMUhQakNxNEZBaGdtTGxCZWxYTUJmYmd4WFdTMloyMjZSR3REZnpydENRTDM4Q2E2a2VvNHJSa1IzRUY0OFBXMFM5bGFod0lGQ1dZOTR5WkE2R2h6bEdqa1hpUDR4QmxESWxFMXhoV2JNRVVXbG5XSlhvZ2tXa01WUWYzajRhWFkzZnRIS1MrTDhMdmNMRjVLQkxWK2FqNVU5NEszSkZoUitLTGw1cUJTZ0NEaFBVZEJvRHk1bWRoZCtYTnN5cWdVMXVQZDRWZ2VDeVd6aVBDMHQveU13YUVheEFQeUR3S1VIRnZnPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48WDUwOUNlcnRpZmljYXRlPk1JSURYVENDQWtXZ0F3SUJBZ0lVUmsvSjBvUXlxbFplQWVZbDVSeDFML2Y4Y2h3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd1BURUxNQWtHQTFVRUJoTUNTVTR4RHpBTkJnTlZCQWdNQmt0bGNtRnNZVEVPTUF3R0ExVUVCd3dGUzI5agphR2t4RFRBTEJnTlZCQW9NQkVKdmVIa3dJQmNOTWpReE1URTRNVFl4TkRFM1doZ1BNekF5TkRBek1qRXhOakUwCk1UZGFNRDB4Q3pBSkJnTlZCQVlUQWtsT01ROHdEUVlEVlFRSURBWkxaWEpoYkdFeERqQU1CZ05WQkFjTUJVdHYKWTJocE1RMHdDd1lEVlFRS0RBUkNiM2g1TUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQwpBUUVBcUk1QmtxV1pNUmZhR3NNQURpY1RYRzZLRlg4MjZuVkhuYXZ2NEQ1VnRWc1Z2bUFyR1JrSVp3V2ppTGQzCklzcmQ0djJOWURhRjFnZjEwVk9ybHRHSlZNZlh2cTNHZEVnKy9nQmErcVdFOG5PQmZBYUhyQ2RlUUZKWmg3clQKOExSdGxjVk9HTGdhcHhhblFBNHFJV0lseWRlVVhFdXZObDBLRUNIR0g4cVhUL3BpMCtxOE9XNkdhbFFLQUFFbgpmUklHQWZSWlVXTFF6bWdxUWRGVERjc205SUhvRkJ0T2F2U05Vb05HVXhxY0tBNFdxbHplaXVUZHNlbXR0V2J1CkYreFpVOFlFY25hTzhDYnJVekpvN21FVm9mVEpZaTNPdm9qNnA2d0h5MGROcnRuYlhYNlhrdTlmUE50eUcrdlYKekF1ZVlHdHFKOEZmZWZxWnBnSE8vVFlqRXdJREFRQUJvMU13VVRBZEJnTlZIUTRFRmdRVVlKMG9mcXp3Zm5RMworMFMxTE9qQlYvbXc3MEl3SHdZRFZSMGpCQmd3Rm9BVVlKMG9mcXp3Zm5RMyswUzFMT2pCVi9tdzcwSXdEd1lEClZSMFRBUUgvQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBbnI2MHBEWVJra0plRm4vK21naXEKS0FJak92RFEzZHN3NUlmLzRzQWxJZGtmZkN2dUhiVHFiSU41NVc4WjNkMjJVS3J0M3pWR3g2cGcyR2ZTVXpwSgpBL2ROeU8yOHdENDVKKzNzYk8wcmpzdDVoSXdZbVliVGltOGltTHZuam1Jd0NDUUNNS3JacEk3bk9WeFdZTWlhCk9lZGZJdTh5d1h4VkdMSkEreEx6WjNJSnBsMDV3eXZ3cXA3QWpyRlNBeUowQnJ5Q1BQZVNjSEhyeC8zWkdxWUUKdDBNYkpyUkpxSkZRZndSQklXc01heWZ2NGp4eDdnaERhRmlrNm11MVFwWmtxK0FlbHEwbW54REE2Umxsd2pBWAphZHFJMXc1d1lIRVhEN3hxcUFudXNyNU5PQ3JidUF6d2hMdWF1MHp3a3IzY2hmZHBVbGd5bzdLTEV4TE54b3ZlCmlnPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48c2FtbDpTdWJqZWN0IHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+amFja3NvbkBleGFtcGxlLmNvbTwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9uT3JBZnRlcj0iMzAwMC0wMS0yMVQxNjozMzoyNy41MzdaIiBSZWNpcGllbnQ9Imh0dHA6Ly9sb2NhbGhvc3Q6NTIyNS9hcGkvb2F1dGgvc2FtbCIvPjwvc2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uPjwvc2FtbDpTdWJqZWN0PjxzYW1sOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDI1LTAxLTIxVDE2OjMzOjI3LjUzN1oiIE5vdE9uT3JBZnRlcj0iMzAwMC0wMS0yMVQxNjozMzoyNy41MzdaIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPmh0dHBzOi8vc2FtbC5ib3h5aHEuY29tPC9zYW1sOkF1ZGllbmNlPjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDpDb25kaXRpb25zPjxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyNS0wMS0yMVQxNjozODoyNy41MzdaIiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmRQcm90ZWN0ZWRUcmFuc3BvcnQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50IHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJpZCIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDp1bnNwZWNpZmllZCI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj4xZGRhOWZiNDkxZGMwMWJkMjRkMjQyM2JhMmYyMmFlNTYxZjU2ZGRmMjM3NmIyOWExMWM4MDI4MWQyMTIwMWY5PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9ImVtYWlsIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVuc3BlY2lmaWVkIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmphY2tzb25AZXhhbXBsZS5jb208L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iZmlyc3ROYW1lIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OnVuc3BlY2lmaWVkIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmphY2tzb248L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0ibGFzdE5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dW5zcGVjaWZpZWQiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+amFja3Nvbjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PC9zYW1sOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==';

  const response = await http.asyncRequest(
    'POST',
    `http://localhost:5225/api/oauth/saml`,
    { SAMLResponse: samlResponse },
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirects: 0,
      tags: {
        sso: 'process_idp_saml_response',
      },
    }
  );

  const isSuccessful = check(response, {
    'processing SAML IdP Response status is 302': (r) => r.status === 302,
  });

  // const result = response.json();
  // console.log(`result`, result);

  // if (result && result.data && result.data.id) {
  //   vuContext[__VU].samlFederationAppId = result.data.id;
  // } else {
  //   console.error('SAMLFederationApp ID not found in response:', JSON.stringify(result));
  // }

  if (!isSuccessful) {
    errorCount.add(1);
    console.error(
      `Processing SAML IdP response failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
    exec.test.abort('Processing SAML IdP response failed');
  }
}
