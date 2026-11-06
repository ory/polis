import crypto from 'crypto';
import {
  OAuthReqBody,
  OAuthReqBodyWithAccessType,
  OAuthReqBodyWithClientId,
  OAuthReqBodyWithResource,
  OAuthTokenReq,
} from '../../src';
import boxyhq from './data/metadata/boxyhq';
import boxyhqNobinding from './data/metadata/nobinding/boxyhq-nobinding';
import boxyhqNoentityID from './data/metadata/noentityID/boxyhq-noentityID';
import exampleOidc from './data/metadata/example.oidc';
import invalidssodescriptor from './data/metadata/invalidSSODescriptor/invalidssodescriptor';

export const GENERIC_ERR_STRING = 'Something wrong happened. Please contact your administrator.';
export const code = '1234567890';
export const token = '24c1550190dd6a5a9bd6fe2a8ff69d593121c7b9';
export const genKey = crypto.randomBytes(32);
export const iv = crypto.randomBytes(12);
export const clientCode = genKey.toString('hex') + '.' + code;
export const clientToken = genKey.toString('hex') + '.' + token;

// BEGIN: Fixtures for authorize
export const authz_request_normal: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
};

export const authz_request_normal_with_code_challenge: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  code_challenge_method: 'S256',
};
export const authz_request_with_forceauthn: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  forceAuthn: 'true',
};

export const authz_request_normal_with_access_type: Partial<OAuthReqBodyWithAccessType> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  access_type: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_id: 'dummy',
};

export const authz_request_normal_with_resource: Partial<OAuthReqBodyWithResource> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  resource: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_id: 'dummy',
};

export const authz_request_normal_with_scope: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  scope: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_id: 'dummy',
};

export const authz_request_normal_oidc_flow: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  scope: `openid`,
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
};

export const redirect_uri_not_set: Partial<OAuthReqBody> = {
  redirect_uri: undefined,
  state: 'state',
};

export const redirect_uri_not_allowed: Partial<OAuthReqBody> = {
  ...authz_request_normal,
  redirect_uri: 'https://example.com/',
};

export const state_not_set: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: undefined,
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
};

export const response_type_not_code: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  response_type: 'token',
};

export const invalid_client_id: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: boxyhq.defaultRedirectUrl,
  state: 'state-123',
  client_id: 'xxxxxxxxx',
};

export const invalid_tenant_product = (product?, tenant?): Partial<OAuthTokenReq> => {
  product = product || boxyhq.product;
  tenant = tenant || boxyhq.tenant;
  return {
    grant_type: 'authorization_code',
    client_id: `tenant=${tenant}&product=${product}`,
    client_secret: 'dummy',
    code: clientCode,
    redirect_uri: boxyhq.defaultRedirectUrl,
  };
};

export const authz_request_oidc_provider: Partial<OAuthReqBodyWithClientId> = {
  redirect_uri: exampleOidc.defaultRedirectUrl,
  state: 'state-123',
  client_id: `tenant=${exampleOidc.tenant}&product=${exampleOidc.product}`,
  scope: 'openid',
};
// END: Fixtures for authorize

// BEGIN: Fixtures for oidcAuthzResponse
const OIDC_PROVIDER_CODE = '99991afdfd';
export const oidc_response = {
  code: OIDC_PROVIDER_CODE,
};
export const oidc_response_with_error = {
  error: 'access_denied',
  error_description: 'The user denied the request',
};

// END: Fixtures for oidcAuthzResponse

// BEGIN: Fixtures for token
const CLIENT_SECRET_VERIFIER = 'TOP-SECRET';
export const bodyWithInvalidCode: Partial<OAuthTokenReq> = {
  grant_type: 'authorization_code',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_secret: CLIENT_SECRET_VERIFIER,
  code: 'invalid-code',
  redirect_uri: boxyhq.defaultRedirectUrl,
};
// invalid redirect_uri
export const bodyWithInvalidRedirectUri: Partial<OAuthTokenReq> = {
  grant_type: 'authorization_code',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_secret: CLIENT_SECRET_VERIFIER,
  code: clientCode,
  redirect_uri: 'http://example.com',
};
export const bodyWithMissingRedirectUri: Partial<OAuthTokenReq> = {
  grant_type: 'authorization_code',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_secret: CLIENT_SECRET_VERIFIER,
  code: clientCode,
};
//encoded clientId and wrong secret
export const bodyWithInvalidClientSecret: Partial<OAuthTokenReq> = {
  grant_type: 'authorization_code',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_secret: 'dummy',
  code: clientCode,
  redirect_uri: boxyhq.defaultRedirectUrl,
};
//unencoded clientId with wrong secret
export const bodyWithUnencodedClientId_InvalidClientSecret_gen = (connectionRecords) => {
  const connectionRecord = connectionRecords.find(
    (record) => `tenant=${record.tenant}&product=${record.product}` === authz_request_normal.client_id
  );
  return {
    grant_type: 'authorization_code',
    client_id: connectionRecord.clientID,
    client_secret: 'dummy',
    code: clientCode,
    redirect_uri: boxyhq.defaultRedirectUrl,
  };
};

export const bodyWithDummyCredentials: Partial<OAuthTokenReq> = {
  grant_type: 'authorization_code',
  client_id: `dummy`,
  client_secret: 'dummy',
  code: clientCode,
  redirect_uri: boxyhq.defaultRedirectUrl,
};

export const token_req_encoded_client_id: Partial<OAuthTokenReq> = {
  grant_type: 'authorization_code',
  client_id: `tenant=${boxyhq.tenant}&product=${boxyhq.product}`,
  client_secret: CLIENT_SECRET_VERIFIER,
  code: clientCode,
  redirect_uri: boxyhq.defaultRedirectUrl,
};

export const token_req_unencoded_client_id_gen = (connectionRecords) => {
  const connectionRecord = connectionRecords.find(
    (record) => `tenant=${record.tenant}&product=${record.product}` === authz_request_normal.client_id
  );
  return {
    grant_type: 'authorization_code',
    client_id: connectionRecord.clientID,
    client_secret: connectionRecord.clientSecret,
    code: clientCode,
    redirect_uri: boxyhq.defaultRedirectUrl,
  };
};

export const token_req_dummy_client_id_idp_saml_login_wrong_secretverifier = {
  grant_type: 'authorization_code',
  code: clientCode,
  client_id: 'dummy',
  client_secret: 'TOP-SECRET-WRONG',
};

export const token_req_dummy_client_id_idp_saml_login = {
  grant_type: 'authorization_code',
  code: clientCode,
  client_id: 'dummy',
  client_secret: 'TOP-SECRET',
};

export const token_req_encoded_client_id_idp_saml_login = {
  grant_type: 'authorization_code',
  code: clientCode,
  client_id: 'tenant=boxyhq.com&product=crm',
  client_secret: 'TOP-SECRET',
};

export const token_req_encoded_client_id_idp_saml_login_wrong_secretverifier = {
  grant_type: 'authorization_code',
  code: clientCode,
  client_id: 'tenant=boxyhq.com&product=crm',
  client_secret: 'TOP-SECRET-WRONG',
};

export const token_req = {
  grant_type: 'authorization_code',
  code: clientCode,
  redirect_uri: boxyhq.defaultRedirectUrl,
};

// END: Fixtures for token

// BEGIN: Fixtures for *_api.test.ts
export const saml_connection = boxyhq;
export const oidc_connection = exampleOidc;
export const saml_connection_entityID_absent = boxyhqNoentityID;
export const saml_connection_binding_absent = boxyhqNobinding;
export const saml_connection_invalid_sso_descriptor = invalidssodescriptor;
// END: Fixtures for *_api.test.ts
