export type ApiSuccess<T> = { data: T; pageToken?: string };

export interface ApiError extends Error {
  info?: string;
  status: number;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
enum DirectorySyncProviders {
  'azure-scim-v2' = 'Entra ID SCIM v2.0',
  'onelogin-scim-v2' = 'OneLogin SCIM v2.0',
  'okta-scim-v2' = 'Okta SCIM v2.0',
  'jumpcloud-scim-v2' = 'JumpCloud v2.0',
  'generic-scim-v2' = 'Generic SCIM v2.0',
  'google' = 'Google',
}

type DirectorySyncEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'group.created'
  | 'group.updated'
  | 'group.deleted'
  | 'group.user_added'
  | 'group.user_removed';

type DirectoryType = keyof typeof DirectorySyncProviders;

type UserWithGroup = User & { group: Group };

type DirectorySyncEventData = User | Group | UserWithGroup;

interface DirectorySyncEvent {
  directory_id: Directory['id'];
  event: DirectorySyncEventType;
  data: DirectorySyncEventData;
  tenant: string;
  product: string;
}

export type Directory = {
  id: string;
  name: string;
  tenant: string;
  product: string;
  type: DirectoryType;
  log_webhook_events: boolean;
  scim: {
    path: string;
    endpoint?: string;
    secret: string;
  };
  webhook: {
    endpoint: string;
    secret: string;
  };
  deactivated?: boolean;
  google_access_token?: string;
  google_refresh_token?: string;
  google_authorization_url?: string;
};

export type User = {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  active: boolean;
  raw?: any;
};

export type Group = {
  id: string;
  name: string;
  raw?: any;
};

export interface WebhookEventLog {
  id: string;
  webhook_endpoint: string;
  created_at: Date;
  status_code?: number;
  delivered?: boolean;
  payload: DirectorySyncEvent | DirectorySyncEvent[];
}

export type AttributeMapping = {
  key: string;
  value: string;
};

export type IdentityFederationApp = {
  id: string;
  type?: string;
  clientID?: string;
  clientSecret?: string;
  redirectUrl?: string[] | string;
  name: string;
  tenant: string;
  product: string;
  acsUrl: string;
  entityId: string;
  logoUrl?: string;
  faviconUrl?: string;
  primaryColor?: string;
  tenants?: string[]; // To support multiple tenants for a single app
  mappings: AttributeMapping[] | null;
  samlAudienceOverride?: string | null;
  ttlInMinutes?: number | null;
};

export interface Trace {
  traceId: string;
  timestamp: number;
  error: string;
  context: {
    [key: string]: unknown;
  };
}

type OIDCIdPInitiatedReq = {
  iss: string;
  login_hint?: string;
  target_link_uri?: string;
};

export interface SSOTrace extends Omit<Trace, 'traceId' | 'timestamp'> {
  timestamp?: number /** Can be passed in from outside else will be set to Date.now() */;
  context: {
    tenant: string;
    product: string;
    clientID: string;
    redirectUri?: string;
    requestedOIDCFlow?: boolean; // Type of OAuth client request
    isSAMLFederated?: boolean; // true if hit the SAML Federation flow
    isOIDCFederated?: boolean; // true if hit the OIDC Federation flow
    isIdPFlow?: boolean; // true if IdP Login flow
    relayState?: string; // RelayState in SP flow
    providerName?: string; // SAML Federation SP
    acsUrl?: string; // ACS Url of SP in SAML Federation flow
    entityId?: string; // Entity ID of SP in SAML Federation flow
    samlRequest?: string; // Generated SAML Request
    samlResponse?: string; // Raw SAML response from IdP
    issuer?: string; // Parsed issuer from samlResponse
    profile?: any; // Profile extracted from samlResponse
    //  OPError attributes from OIDC provider authorization response: https://github.com/panva/node-openid-client/blob/main/docs/README.md#class-operror
    error?: string;
    error_description?: string;
    error_uri?: string;
    session_state_from_op_error?: string;
    scope_from_op_error?: string;
    stack?: string;
    oidcTokenSet?: { id_token?: string; access_token?: string };
    oidcIdPRequest?: OIDCIdPInitiatedReq;
    oAuthStage?: 'token_fetch' | 'userinfo_fetch';
  };
}

export type SetupLinkService = 'sso' | 'dsync';

export type SetupLink = {
  setupID: string;
  tenant: string;
  product: string;
  validTill: number;
  url: string;
  service: SetupLinkService;
};

// Branding options
export type Branding = {
  logoUrl: string;
  faviconUrl: string;
  primaryColor: string;
  companyName: string;
};
