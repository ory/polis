import type { JWK } from 'jose';
import type { ServerMetadata } from 'openid-client';

export * from './ee/identity-federation/types';
export * from './sso-traces/types';
export * from './directory-sync/types';
export * from './event/types';

import db from './db/db';
import { EventCallback } from './typings';

export type DB = Awaited<ReturnType<typeof db.new>>;

export interface OryRes {
  projectId?: string;
  domains?: string[];
  organizationId?: string;
  error: any | undefined;
}

export interface OryConfig extends OryRes {
  sdkToken?: string;
}

export interface SSOConnection {
  defaultRedirectUrl: string;
  redirectUrl: string[] | string;
  tenant: string;
  product: string;
  name?: string;
  label?: string;
  description?: string;
  sortOrder?: number | null;
  acsUrlOverride?: string;
  samlAudienceOverride?: string;
}

export interface SAMLSSOConnection extends SSOConnection {
  forceAuthn?: boolean | string;
  identifierFormat?: string;
}

export interface SAMLSSOConnectionWithRawMetadata extends SAMLSSOConnection {
  rawMetadata: string;
  encodedRawMetadata?: never;
  metadataUrl?: string;
}

export interface SAMLSSOConnectionWithEncodedMetadata extends SAMLSSOConnection {
  rawMetadata?: never;
  encodedRawMetadata: string;
  metadataUrl?: string;
}

interface OIDCSSOConnection extends SSOConnection {
  oidcClientId: string;
  oidcClientSecret: string;
}

export interface OIDCSSOConnectionWithMetadata extends OIDCSSOConnection {
  oidcDiscoveryUrl?: never;
  oidcMetadata: ServerMetadata;
}

export interface OIDCSSOConnectionWithDiscoveryUrl extends OIDCSSOConnection {
  oidcDiscoveryUrl: string;
  oidcMetadata?: never;
}

export interface SAMLSSORecord extends SAMLSSOConnection {
  clientID: string; // set by Jackson
  clientSecret: string; // set by Jackson
  metadataUrl?: string;
  idpMetadata: {
    entityID: string;
    loginType?: string;
    provider: string | 'Unknown';
    friendlyProviderName: string | null;
    slo: { postUrl?: string; redirectUrl?: string };
    sso: { postUrl?: string; redirectUrl?: string };
    thumbprint?: string;
    publicKey?: string;
    validTo?: string;
  };
  deactivated?: boolean;
}

export interface OIDCSSORecord extends SSOConnection {
  clientID: string; // set by Jackson
  clientSecret: string; // set by Jackson
  oidcProvider: {
    provider: string | 'Unknown';
    friendlyProviderName: string | null;
    discoveryUrl?: string;
    metadata?: ServerMetadata;
    clientId: string;
    clientSecret: string;
  };
  deactivated?: boolean;
}

export type ConnectionType = 'saml' | 'oidc';

type ClientIDQuery = { clientID: string };

type TenantQuery = { tenant: string; product: string; strategy?: ConnectionType };

type TenantProduct = { tenant: string; product: string };

export type GetConnectionsQuery =
  | ClientIDQuery
  | TenantQuery
  | { entityId: string }
  | { tenant: string[]; product: string; sort?: boolean };

export type GetIDPEntityIDBody = TenantProduct;
export type DelConnectionsQuery = (ClientIDQuery & { clientSecret: string }) | TenantQuery;

export type GetConfigQuery = ClientIDQuery | Omit<TenantQuery, 'strategy'>;
export type DelConfigQuery = (ClientIDQuery & { clientSecret: string }) | Omit<TenantQuery, 'strategy'>;

export type UpdateConnectionParams = TenantProduct & {
  clientID: string;
  clientSecret: string;
  name?: string;
  label?: string;
  description?: string;
  defaultRedirectUrl?: string;
  redirectUrl?: string[] | string;
  deactivated?: boolean;
  sortOrder?: number | null;
};

export type UpdateSAMLConnectionParams = UpdateConnectionParams & {
  encodedRawMetadata?: string;
  metadataUrl?: string;
  rawMetadata?: string;
  forceAuthn?: boolean;
  identifierFormat?: string;
  acsUrlOverride?: string;
  samlAudienceOverride?: string;
};

export type UpdateOIDCConnectionParams = UpdateConnectionParams & {
  oidcDiscoveryUrl?: string;
  oidcMetadata?: ServerMetadata;
  oidcClientId?: string;
  oidcClientSecret?: string;
};

export interface IConnectionAPIController {
  /**
   * @deprecated Use `createSAMLConnection` instead.
   */
  config(body: SAMLSSOConnection): Promise<SAMLSSORecord>;
  createSAMLConnection(
    body: SAMLSSOConnectionWithRawMetadata | SAMLSSOConnectionWithEncodedMetadata
  ): Promise<SAMLSSORecord>;
  createOIDCConnection(
    body: OIDCSSOConnectionWithDiscoveryUrl | OIDCSSOConnectionWithMetadata
  ): Promise<OIDCSSORecord>;
  /**
   * @deprecated Use `updateSAMLConnection` instead.
   */
  updateConfig(body: UpdateSAMLConnectionParams): Promise<void>;
  updateSAMLConnection(body: UpdateSAMLConnectionParams): Promise<void>;
  updateOIDCConnection(body: UpdateOIDCConnectionParams): Promise<void>;
  getConnections(body: GetConnectionsQuery): Promise<Array<SAMLSSORecord | OIDCSSORecord>>;
  getIDPEntityID(body: GetIDPEntityIDBody): string;
  /**
   * @deprecated Use `getConnections` instead.
   */
  getConfig(body: GetConfigQuery): Promise<SAMLSSORecord | Record<string, never>>;
  deleteConnections(body: DelConnectionsQuery): Promise<void>;
  /**
   * @deprecated Use `deleteConnections` instead.
   */
  deleteConfig(body: DelConfigQuery): Promise<void>;
  getConnectionsByProduct(
    body: GetByProductParams
  ): Promise<{ data: (SAMLSSORecord | OIDCSSORecord)[]; pageToken?: string }>;
  getCount(idx?: Index): Promise<number | undefined>;
}

export interface IOAuthController {
  authorize(body: OAuthReq): Promise<{ redirect_url?: string; authorize_form?: string; error?: string }>;
  samlResponse(
    body: SAMLResponsePayload
  ): Promise<{ redirect_url?: string; app_select_form?: string; response_form?: string; error?: string }>;
  oidcAuthzResponse(
    body: OIDCAuthzResponsePayload
  ): Promise<{ redirect_url?: string; response_form?: string; error?: string }>;
  token(body: OAuthTokenReq): Promise<OAuthTokenRes>;
  userInfo(token: string): Promise<Profile>;
}

export interface IAdminController {
  getAllConnection(pageOffset?: number, pageLimit?: number, pageToken?: string);
  getAllSSOTraces(pageOffset: number, pageLimit: number, pageToken?: string);
  getSSOTraceById(traceId: string);
  getTracesByProduct(product: string, pageOffset: number, pageLimit: number, pageToken?: string);
  deleteTracesByProduct(product: string);
}

export interface IHealthCheckController {
  status(): Promise<{ status: number }>;
  init(): Promise<void>;
}

export interface ILogoutController {
  createRequest(body: SLORequestParams): Promise<{ logoutUrl: string | null; logoutForm: string | null }>;
  handleResponse(body: SAMLResponsePayload): Promise<any>;
}

export interface IOidcDiscoveryController {
  openidConfig(): {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    jwks_uri: string;
    response_types_supported: Array<string>;
    subject_types_supported: Array<string>;
    id_token_signing_alg_values_supported: Array<string>;
    grant_types_supported: Array<string>;
    code_challenge_methods_supported: Array<string>;
  };

  jwks(): Promise<{ keys: JWK[] }>;
}

export interface OAuthReqBody {
  state: string;
  response_type: 'code';
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'plain' | 'S256' | '';
  scope?: string;
  nonce?: string;
  idp_hint?: string;
  forceAuthn?: string;
  login_hint?: string;
  [key: string]: unknown;
}

export interface OAuthReqBodyWithClientId extends OAuthReqBody {
  client_id: string;
  tenant?: undefined;
  product?: undefined;
  access_type?: undefined;
  resource?: undefined;
}

export interface OAuthReqBodyWithTenantProduct extends OAuthReqBody {
  client_id: 'dummy';
  tenant: string;
  product: string;
  access_type?: undefined;
  resource?: undefined;
}

export interface OAuthReqBodyWithAccessType extends OAuthReqBody {
  client_id: 'dummy';
  access_type: string;
  tenant?: undefined;
  product?: undefined;
  resource?: undefined;
}

export interface OAuthReqBodyWithResource extends OAuthReqBody {
  client_id: 'dummy';
  resource: string;
  tenant?: undefined;
  product?: undefined;
  access_type?: undefined;
}

export type OAuthReq =
  | OAuthReqBodyWithClientId
  | OAuthReqBodyWithTenantProduct
  | OAuthReqBodyWithAccessType
  | OAuthReqBodyWithResource;

export type OIDCIdPInitiatedReq = { iss: string; login_hint?: string; target_link_uri?: string };

export interface SAMLResponsePayload {
  SAMLResponse: string;
  RelayState: string;
  idp_hint?: string;
}

export type OIDCAuthzResponsePayload = Record<string, string>;

interface OAuthTokenReqBody {
  code: string;
  grant_type: 'authorization_code';
  redirect_uri: string;
}

export interface OAuthTokenReqWithCodeVerifier extends OAuthTokenReqBody {
  code_verifier: string;
  client_id?: never;
  client_secret?: never;
}

export interface OAuthTokenReqWithCredentials extends OAuthTokenReqBody {
  code_verifier?: never;
  client_id: string;
  client_secret: string;
}

export type OAuthTokenReq = OAuthTokenReqWithCodeVerifier | OAuthTokenReqWithCredentials;

export interface OAuthTokenRes {
  access_token: string;
  id_token?: string;
  token_type: 'bearer';
  expires_in: number;
}

export interface Profile {
  id: string;
  idHash: string;
  sub?: string;
  email: string;
  firstName: string;
  lastName: string;
  roles?: string[];
  groups?: string[];
  requested: Record<string, string>;
  raw: any;
}

export interface Index {
  name: string;
  value: string;
}

export interface Records<T = any> {
  data: T[];
  pageToken?: string;
}

export interface DatabaseDriver {
  getAll(
    namespace: string,
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records>;
  get(namespace: string, key: string): Promise<any>;
  put(namespace: string, key: string, val: any, ttl: number, ...indexes: Index[]): Promise<any>;
  delete(namespace: string, key: string): Promise<any>;
  getByIndex(
    namespace: string,
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records>;
  getCount?(namespace: string, idx?: Index): Promise<number | undefined>;
  deleteMany(namespace: string, keys: string[]): Promise<void>;
  close(): Promise<void>;
  getStats(): Record<string, number>;
}

export interface Storable {
  getAll(
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records>;
  get(key: string): Promise<any>;
  put(key: string, val: any, ...indexes: Index[]): Promise<any>;
  delete(key: string): Promise<any>;
  getByIndex(
    idx: Index,
    pageOffset?: number,
    pageLimit?: number,
    pageToken?: string,
    sortOrder?: SortOrder
  ): Promise<Records>;
  getCount(idx?: Index): Promise<number | undefined>;
  deleteMany(keys: string[]): Promise<void>;
}

export interface DatabaseStore {
  store(namespace: string): Storable;
}

export interface Encrypted {
  iv?: string;
  tag?: string;
  value: string;
}

export type EncryptionKey = any;

export type DatabaseEngine = 'redis' | 'sql' | 'mongo' | 'mem' | 'planetscale' | 'dynamodb';

export type DatabaseType = 'postgres' | 'mysql' | 'mariadb' | 'mssql' | 'sqlite' | 'cockroachdb';

export interface DatabaseOption {
  engine?: DatabaseEngine;
  url?: string;
  type?: DatabaseType;
  ttl?: number;
  cleanupLimit?: number;
  encryptionKey?: string;
  pageLimit?: number;
  ssl?: any;
  dynamodb?: { region?: string; readCapacityUnits?: number; writeCapacityUnits?: number };
  manualMigration?: boolean;
}

export interface DatabaseDriverOption {
  driver: DatabaseDriver;
  encryptionKey?: string;
  ttl?: number;
  cleanupLimit?: number;
  pageLimit?: number;
  manualMigration?: boolean;
}

export interface JacksonOption {
  externalUrl: string;
  samlPath: string;
  acsUrl?: string;
  oidcPath?: string;
  samlAudience?: string;
  preLoadedConnection?: string;
  idpEnabled?: boolean;
  db: DatabaseOption | DatabaseDriverOption;
  clientSecretVerifier?: string;
  idpDiscoveryPath?: string;
  scimPath?: string;
  openid?: {
    jwsAlg?: string;
    jwtSigningKeys?: { private: string; public: string };
    requestProfileScope?: boolean; // defaults to true
    forwardOIDCParams?: boolean; // defaults to false
    subjectPrefix?: boolean; // defaults to false
  };
  certs?: { publicKey: string; privateKey: string };
  boxyhqLicenseKey?: string;
  noAnalytics?: boolean;
  webhook?: Webhook;
  dsync?: {
    webhookBatchSize?: number;
    webhookBatchCronInterval?: number;
    debugWebhooks?: boolean;
    providers?: {
      google: {
        clientId: string;
        clientSecret: string;
        authorizePath: string;
        callbackPath: string;
        cronInterval?: number;
      };
    };
    callback?: EventCallback;
  };

  /**  The number of days a setup link is valid for. Defaults to 3 days. */
  setupLinkExpiryDays?: number;
  boxyhqHosted?: boolean;

  ssoTraces?: SSOTracesOption;
  logger?: {
    info?: (msg: string, err?: any) => void;
    warn?: (msg: string, err?: any) => void;
    error?: (msg: string, err?: any) => void;
  };
  flattenRawClaims?: boolean;
  jsonErrorPage?: boolean;
}

export interface SLORequestParams {
  nameId: string;
  tenant: string;
  product: string;
  redirectUrl?: string;
}

interface Metadata {
  sso: { postUrl?: string; redirectUrl: string };
  slo: { redirectUrl?: string; postUrl?: string };
  entityID: string;
  thumbprint: string;
  loginType: 'idp' | 'sp';
  provider: string;
}

export interface SAMLConnection {
  idpMetadata: Metadata;
  defaultRedirectUrl: string;
}

// See Error Response section in https://www.oauth.com/oauth2-servers/authorization/the-authorization-response/
export interface OAuthErrorHandlerParams {
  error:
    | 'invalid_request'
    | 'access_denied'
    | 'unauthorized_client'
    | 'unsupported_response_type'
    | 'invalid_scope'
    | 'server_error'
    | 'temporarily_unavailable'
    | OIDCErrorCodes;
  error_description?: string;
  redirect_uri: string;
  state?: string;
}

export type OIDCErrorCodes =
  | 'interaction_required'
  | 'login_required'
  | 'account_selection_required'
  | 'consent_required'
  | 'invalid_request_uri'
  | 'invalid_request_object'
  | 'request_not_supported'
  | 'request_uri_not_supported'
  | 'registration_not_supported';

export interface ISPSSOConfig {
  oidcRedirectURI: string;
  get(): Promise<{
    acsUrl: string;
    entityId: string;
    response: string;
    assertionSignature: string;
    signatureAlgorithm: string;
    publicKey: string;
    publicKeyString: string;
  }>;
  toXMLMetadata(boolean?, string?): Promise<string>;
}

export interface ApiError {
  message: string;
  code: number;
}

export type SetupLink = {
  setupID: string;
  tenant: string;
  name?: string;
  description?: string;
  defaultRedirectUrl?: string;
  redirectUrl?: string;
  product: string;
  url: string;
  service: SetupLinkService;
  validTill: number;
  webhook_url?: string;
  webhook_secret?: string;
};

export type SetupLinkCreatePayload =
  | (Pick<SetupLink, 'name' | 'tenant' | 'product' | 'webhook_url' | 'webhook_secret'> & {
      service: 'dsync';
      regenerate?: boolean;
      expiryDays?: number;
    })
  | (Pick<SetupLink, 'name' | 'tenant' | 'product' | 'description' | 'defaultRedirectUrl' | 'redirectUrl'> & {
      service: 'sso';
      regenerate?: boolean;
      expiryDays?: number;
    });

export type SetupLinkService = 'sso' | 'dsync';

// Admin Portal settings
export type AdminPortalSettings = { branding: AdminPortalBranding };

// Admin Portal branding options
export type AdminPortalBranding = {
  logoUrl: string | null;
  faviconUrl: string | null;
  primaryColor: string | null;
  companyName: string | null;
};

export type Webhook = { endpoint: string; secret: string };

export type GetByProductParams = {
  product: string;
  pageOffset?: number;
  pageLimit?: number;
  pageToken?: string;
};

export type SortOrder = 'ASC' | 'DESC';

export interface ProductConfig {
  id: string;
  name: string | null;
  teamId: string | null;
  teamName: string | null;
  logoUrl: string | null;
  primaryColor: string | null;
  faviconUrl: string | null;
  companyName: string | null;
  development?: boolean;
}

export interface SSOTracesOption {
  disable?: boolean;
  redact?: boolean;
  ttl?: number;
}

export type RequiredLogger = {
  info: (msg: string, err?: any) => void;
  error: (msg: string, err?: any) => void;
  warn: (msg: string, err?: any) => void;
};

export type JacksonOptionWithRequiredLogger = Omit<JacksonOption, 'logger'> & { logger: RequiredLogger };
