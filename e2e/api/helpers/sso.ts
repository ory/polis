import { type APIRequestContext, expect } from '@playwright/test';

const rawMetadata = `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://saml.example.com/entityid" validUntil="2033-01-05T12:15:32.426Z"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIIC4jCCAcoCCQC33wnybT5QZDANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJV SzEPMA0GA1UECgwGQm94eUhRMRIwEAYDVQQDDAlNb2NrIFNBTUwwIBcNMjIwMjI4 MjE0NjM4WhgPMzAyMTA3MDEyMTQ2MzhaMDIxCzAJBgNVBAYTAlVLMQ8wDQYDVQQK DAZCb3h5SFExEjAQBgNVBAMMCU1vY2sgU0FNTDCCASIwDQYJKoZIhvcNAQEBBQAD ggEPADCCAQoCggEBALGfYettMsct1T6tVUwTudNJH5Pnb9GGnkXi9Zw/e6x45DD0 RuRONbFlJ2T4RjAE/uG+AjXxXQ8o2SZfb9+GgmCHuTJFNgHoZ1nFVXCmb/Hg8Hpd 4vOAGXndixaReOiq3EH5XvpMjMkJ3+8+9VYMzMZOjkgQtAqO36eAFFfNKX7dTj3V pwLkvz6/KFCq8OAwY+AUi4eZm5J57D31GzjHwfjH9WTeX0MyndmnNB1qV75qQR3b 2/W5sGHRv+9AarggJkF+ptUkXoLtVA51wcfYm6hILptpde5FQC8RWY1YrswBWAEZ NfyrR4JeSweElNHg4NVOs4TwGjOPwWGqzTfgTlECAwEAATANBgkqhkiG9w0BAQsF AAOCAQEAAYRlYflSXAWoZpFfwNiCQVE5d9zZ0DPzNdWhAybXcTyMf0z5mDf6FWBW 5Gyoi9u3EMEDnzLcJNkwJAAc39Apa4I2/tml+Jy29dk8bTyX6m93ngmCgdLh5Za4 khuU3AM3L63g7VexCuO7kwkjh/+LqdcIXsVGO6XDfu2QOs1Xpe9zIzLpwm/RNYeX UjbSj5ce/jekpAw7qyVVL4xOyh8AtUW1ek3wIw1MJvEgEPt0d16oshWJpoS1OT8L r/22SvYEo3EmSGdTVGgk3x3s+A0qWAqTcyjr7Q4s/GKYRFfomGwz0TZ4Iw1ZN99M m0eo2USlSRTVl7QHRTuiuSThHpLKQQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://mocksaml.com/api/saml/sso" /><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://mocksaml.com/api/saml/sso" /></md:IDPSSODescriptor></md:EntityDescriptor>`;

export const newConnection = {
  tenant: 'api-boxyhq',
  product: 'api-saml-jackson',
  defaultRedirectUrl: 'http://localhost:3366/login/saml',
  redirectUrl: ['http://localhost:3366/*'],
  name: 'connection name',
  description: 'connection description',
  rawMetadata,
};

export const expectedConnection = {
  tenant: newConnection.tenant,
  product: newConnection.product,
  defaultRedirectUrl: newConnection.defaultRedirectUrl,
  redirectUrl: newConnection.redirectUrl,
  name: newConnection.name,
  description: newConnection.description,
  forceAuthn: false,
  idpMetadata: {
    sso: {
      postUrl: 'https://mocksaml.com/api/saml/sso',
      redirectUrl: 'https://mocksaml.com/api/saml/sso',
    },
    slo: {},
    entityID: 'https://saml.example.com/entityid',
    loginType: 'idp',
    provider: 'saml.example.com',
  },
};

type NewConnection = typeof newConnection;

// Get the raw metadata with the entityID replaced
export const getRawMetadata = (entityId: string) => {
  return rawMetadata.replace('https://saml.example.com/entityid', entityId);
};

// Create a connection
export const createConnection = async (request: APIRequestContext, payload: NewConnection) => {
  const response = await request.post('/api/v1/sso', {
    data: {
      ...payload,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

// Get a connection
export const getConnection = async (
  request: APIRequestContext,
  { tenant, product }: { tenant: string; product: string }
) => {
  const response = await request.get('/api/v1/sso', {
    params: {
      tenant,
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

// Get connections by product
export const getConnectionByProduct = async (request: APIRequestContext, product: string) => {
  const response = await request.get('/api/v1/sso/product', {
    params: {
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

// Delete a connection
export const deleteConnection = async (
  request: APIRequestContext,
  { tenant, product }: { tenant: string; product: string }
) => {
  const response = await request.delete('/api/v1/sso', {
    params: {
      tenant,
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(204);
};

// get a sso trace by id
export const getSSOTraceById = async (request: APIRequestContext, id: string) => {
  const response = await request.get('/api/v1/sso-traces', {
    params: {
      id,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

// get sso traces by product
export const getSSOTracesByProduct = async (request: APIRequestContext, product: string) => {
  const response = await request.get('/api/v1/sso-traces/product', {
    params: {
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

// Delete sso traces by product
export const deleteSSOTraces = async (request: APIRequestContext, product: string) => {
  const response = await request.delete('/api/v1/sso-traces/product', {
    params: {
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(204);
};

// Count sso traces by product
export const countSSOTracesByProduct = async (request: APIRequestContext, product: string) => {
  const response = await request.get('/api/v1/sso-traces/product/count', {
    params: {
      product,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};
