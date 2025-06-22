import type {
  DatabaseEngine,
  DatabaseOption,
  DatabaseType,
  JacksonOption,
  SSOTracesOption,
} from '@boxyhq/saml-jackson';

const samlPath = '/api/oauth/saml';
const oidcPath = '/api/oauth/oidc';
const idpDiscoveryPath = '/idp/select';
const googleDSyncAuthorizePath = '/api/scim/oauth/authorize';
const googleDSyncCallbackPath = '/api/scim/oauth/callback';

const hostUrl = process.env.HOST_URL || 'localhost';
const hostPort = Number(process.env.PORT || '5225');
const externalUrl = process.env.EXTERNAL_URL || 'http://' + hostUrl + ':' + hostPort;
const apiKeys = (process.env.JACKSON_API_KEYS || '').split(',');
const acsUrl = process.env.ACS_URL || externalUrl + samlPath;

let ssl;
if (process.env.DB_SSL === 'true') {
  ssl = { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' };
}

export const setupLinkExpiryDays = process.env.SETUP_LINK_EXPIRY_DAYS
  ? Number(process.env.SETUP_LINK_EXPIRY_DAYS)
  : 3;

const db: DatabaseOption = {
  engine: process.env.DB_ENGINE ? <DatabaseEngine>process.env.DB_ENGINE : undefined,
  url: process.env.DB_URL || process.env.DATABASE_URL,
  type: process.env.DB_TYPE ? <DatabaseType>process.env.DB_TYPE : undefined,
  ttl: process.env.DB_TTL ? Number(process.env.DB_TTL) : undefined,
  cleanupLimit: process.env.DB_CLEANUP_LIMIT ? Number(process.env.DB_CLEANUP_LIMIT) : undefined,
  encryptionKey: process.env.DB_ENCRYPTION_KEY,
  pageLimit: process.env.DB_PAGE_LIMIT ? Number(process.env.DB_PAGE_LIMIT) : undefined,
  ssl,
  dynamodb: {
    region: process.env.DB_DYNAMODB_REGION,
    readCapacityUnits: process.env.DB_DYNAMODB_RCUS ? Number(process.env.DB_DYNAMODB_RCUS) : undefined,
    writeCapacityUnits: process.env.DB_DYNAMODB_RCUS ? Number(process.env.DB_DYNAMODB_WCUS) : undefined,
  },
  manualMigration: process.env.DB_MANUAL_MIGRATION === 'true',
};

// ssoTraces options
const ssoTraces: SSOTracesOption = {
  disable: process.env.SSO_TRACES_DISABLE === 'true',
  redact: process.env.SSO_TRACES_REDACT === 'true',
  ttl: process.env.SSO_TRACES_TTL ? Number(process.env.SSO_TRACES_TTL) * 60 * 60 : undefined,
};

/** Indicates if the Jackson instance is hosted (i.e. not self-hosted) */
export const boxyhqHosted = process.env.BOXYHQ_HOSTED === '1';

const jacksonOptions: JacksonOption = {
  externalUrl,
  samlPath,
  acsUrl,
  oidcPath,
  idpDiscoveryPath,
  samlAudience: process.env.SAML_AUDIENCE,
  preLoadedConnection: process.env.PRE_LOADED_CONNECTION || process.env.PRE_LOADED_CONFIG,
  idpEnabled: process.env.IDP_ENABLED === 'true',
  db,
  clientSecretVerifier: process.env.CLIENT_SECRET_VERIFIER,
  openid: {
    jwsAlg: process.env.OPENID_JWS_ALG,
    jwtSigningKeys: {
      private: process.env.OPENID_RSA_PRIVATE_KEY || '',
      public: process.env.OPENID_RSA_PUBLIC_KEY || '',
    },
    requestProfileScope: process.env.OPENID_REQUEST_PROFILE_SCOPE === 'false' ? false : true,
    forwardOIDCParams: process.env.OPENID_REQUEST_FORWARD_PARAMS === 'true' ? true : false,
    subjectPrefix: process.env.OPENID_SUBJECT_PREFIX === 'true' ? true : false,
  },
  certs: { publicKey: process.env.PUBLIC_KEY || '', privateKey: process.env.PRIVATE_KEY || '' },
  boxyhqLicenseKey: process.env.BOXYHQ_LICENSE_KEY,
  noAnalytics:
    process.env.DO_NOT_TRACK === '1' ||
    process.env.DO_NOT_TRACK === 'true' ||
    process.env.BOXYHQ_NO_ANALYTICS === '1' ||
    process.env.BOXYHQ_NO_ANALYTICS === 'true',
  webhook: { endpoint: process.env.WEBHOOK_URL || '', secret: process.env.WEBHOOK_SECRET || '' },
  dsync: {
    webhookBatchSize: process.env.DSYNC_WEBHOOK_BATCH_SIZE
      ? Number(process.env.DSYNC_WEBHOOK_BATCH_SIZE)
      : undefined,
    webhookBatchCronInterval: process.env.DSYNC_WEBHOOK_BATCH_CRON_INTERVAL
      ? Number(process.env.DSYNC_WEBHOOK_BATCH_CRON_INTERVAL)
      : undefined,
    debugWebhooks: process.env.DSYNC_DEBUG_WEBHOOKS === 'true',
    providers: {
      google: {
        clientId: process.env.DSYNC_GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: process.env.DSYNC_GOOGLE_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET || '',
        authorizePath: googleDSyncAuthorizePath,
        callbackPath: googleDSyncCallbackPath,
        cronInterval: process.env.DSYNC_GOOGLE_CRON_INTERVAL
          ? Number(process.env.DSYNC_GOOGLE_CRON_INTERVAL)
          : undefined,
      },
    },
  },
  setupLinkExpiryDays,
  boxyhqHosted,
  ssoTraces,
  flattenRawClaims: process.env.FLATTEN_RAW_CLAIMS === 'true',
  jsonErrorPage: process.env.JSON_ERROR_PAGE === 'true',
};

const adminPortalSSODefaults = {
  tenant: process.env.ADMIN_PORTAL_SSO_TENANT || '_jackson_boxyhq',
  product: process.env.ADMIN_PORTAL_SSO_PRODUCT || '_jackson_admin_portal',
  redirectUrl: [externalUrl],
  defaultRedirectUrl: `${externalUrl}/admin/auth/idp-login`,
};

const adminPortal = {
  hideIdentityFederation: process.env.ADMIN_PORTAL_HIDE_IDENTITY_FEDERATION === 'true',
  hideDirectorySync: process.env.ADMIN_PORTAL_HIDE_DIRECTORY_SYNC === 'true',
};

const loggerOptions = { file: process.env.LOG_FILE, level: process.env.LOG_LEVEL };

export { adminPortalSSODefaults };
export { adminPortal };
export { apiKeys };
export { jacksonOptions };
export { loggerOptions };
