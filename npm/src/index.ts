import type {
  IDirectorySyncController,
  JacksonOption,
  JacksonOptionWithRequiredLogger,
  RequiredLogger,
} from './typings';
import DB from './db/db';
import defaultDb from './db/defaultDb';
import loadConnection from './loadConnection';
import { AdminController } from './controller/admin';
import { ConnectionAPIController } from './controller/api';
import { OAuthController } from './controller/oauth';
import { LogoutController } from './controller/logout';
import initDirectorySync from './directory-sync';
import { OidcDiscoveryController } from './controller/oidc-discovery';
import { SPSSOConfig } from './controller/sp-config';
import { SetupLinkController } from './controller/setup-link';
import { AnalyticsController } from './controller/analytics';
import * as x509 from './saml/x509';
import initIdentityFederation, { type IIdentityFederationController } from './ee/identity-federation';
import checkLicense from './ee/common/checkLicense';
import { BrandingController } from './ee/branding';
import SSOTraces from './sso-traces';
import EventController from './event';
import { ProductController } from './ee/product';

const TRACES_TTL_DEFAULT = 7 * 24 * 60 * 60;

const defaultOpts = (opts: JacksonOption): JacksonOptionWithRequiredLogger => {
  const newOpts = { ...opts };

  if (!newOpts.externalUrl) {
    throw new Error('externalUrl is required');
  }

  if (!newOpts.samlPath) {
    throw new Error('samlPath is required');
  }

  if (!newOpts.acsUrl) {
    newOpts.acsUrl = newOpts.externalUrl + newOpts.samlPath;
  }

  newOpts.scimPath = newOpts.scimPath || '/api/scim/v2.0';

  newOpts.samlAudience = newOpts.samlAudience || 'https://saml.boxyhq.com';
  // path to folder containing static IdP connections that will be preloaded. This is useful for self-hosted deployments that only have to support a single tenant (or small number of known tenants).
  newOpts.preLoadedConnection = newOpts.preLoadedConnection || '';

  newOpts.idpEnabled = newOpts.idpEnabled === true;
  defaultDb(newOpts);

  newOpts.clientSecretVerifier = newOpts.clientSecretVerifier || 'dummy';
  newOpts.db.pageLimit = newOpts.db.pageLimit || 50;

  newOpts.openid = newOpts.openid || {};
  newOpts.openid.jwsAlg = newOpts.openid.jwsAlg || 'RS256';
  newOpts.openid.requestProfileScope = newOpts.openid?.requestProfileScope ?? true;
  newOpts.openid.forwardOIDCParams = newOpts.openid?.forwardOIDCParams ?? false;

  newOpts.boxyhqLicenseKey = newOpts.boxyhqLicenseKey || undefined;

  newOpts.ssoTraces = newOpts.ssoTraces || {};
  newOpts.ssoTraces.ttl = newOpts.ssoTraces?.ttl || TRACES_TTL_DEFAULT;

  const defaultLogger: RequiredLogger = {
    info: console.info.bind(console),
    error: console.error.bind(console),
    warn: console.warn.bind(console),
  };

  newOpts.logger = { ...defaultLogger, ...newOpts.logger } as RequiredLogger;

  return newOpts as JacksonOptionWithRequiredLogger;
};

export const controllers = async (
  opts: JacksonOption
): Promise<{
  apiController: ConnectionAPIController;
  connectionAPIController: ConnectionAPIController;
  oauthController: OAuthController;
  adminController: AdminController;
  logoutController: LogoutController;
  setupLinkController: SetupLinkController;
  directorySyncController: IDirectorySyncController;
  oidcDiscoveryController: OidcDiscoveryController;
  spConfig: SPSSOConfig;
  identityFederationController: IIdentityFederationController;
  brandingController: IBrandingController;
  checkLicense: () => Promise<boolean>;
  productController: ProductController;
  close: () => Promise<void>;
}> => {
  opts = defaultOpts(opts);

  const logger = opts.logger as RequiredLogger;
  const db = await DB.new({ db: opts.db, logger });

  const connectionStore = db.store('saml:config');
  const sessionStore = db.store('oauth:session', opts.db.ttl);
  const codeStore = db.store('oauth:code', opts.db.ttl);
  const tokenStore = db.store('oauth:token', opts.db.ttl);
  const setupLinkStore = db.store('setup:link');
  const certificateStore = db.store('x509:certificates');
  const settingsStore = db.store('portal:settings');
  const productStore = db.store('product:config');
  const tracesStore = db.store('saml:tracer', opts.ssoTraces?.ttl);

  const ssoTraces = new SSOTraces({ tracesStore, opts });
  const eventController = new EventController({ opts: opts as JacksonOptionWithRequiredLogger });
  const productController = new ProductController({
    productStore,
    opts: opts as JacksonOptionWithRequiredLogger,
  });

  const connectionAPIController = new ConnectionAPIController({
    connectionStore,
    opts,
    eventController,
  });
  const adminController = new AdminController({ connectionStore, ssoTraces });
  const setupLinkController = new SetupLinkController({ setupLinkStore, opts });

  // Create default certificate if it doesn't exist.
  await x509.init(certificateStore, opts);

  // Enterprise Features
  const identityFederationController = await initIdentityFederation({
    db,
    opts: opts as JacksonOptionWithRequiredLogger,
    ssoTraces,
  });
  const brandingController = new BrandingController({ store: settingsStore, opts });

  const oauthController = new OAuthController({
    connectionStore,
    sessionStore,
    codeStore,
    tokenStore,
    ssoTraces,
    opts,
    idFedApp: identityFederationController.app,
  });

  const logoutController = new LogoutController({ connectionStore, sessionStore, opts });

  const oidcDiscoveryController = new OidcDiscoveryController({ opts });
  const spConfig = new SPSSOConfig(opts);
  const directorySyncController = await initDirectorySync({
    db,
    opts: opts as JacksonOptionWithRequiredLogger,
    eventController,
  });

  // write pre-loaded connections if present
  const preLoadedConnection = opts.preLoadedConnection;
  if (preLoadedConnection && preLoadedConnection.length > 0) {
    const connections = await loadConnection(preLoadedConnection);

    for (const connection of connections) {
      if ('oidcDiscoveryUrl' in connection || 'oidcMetadata' in connection) {
        await connectionAPIController.createOIDCConnection(connection);
      } else {
        await connectionAPIController.createSAMLConnection(connection);
      }

      logger.info(`loaded connection for tenant "${connection.tenant}" and product "${connection.product}"`);
    }
  }

  if (!opts.noAnalytics) {
    logger.info(
      'Anonymous analytics enabled. You can disable this by setting the DO_NOT_TRACK=1 or BOXYHQ_NO_ANALYTICS=1 environment variables'
    );
    const analyticsStore = db.store('_analytics:events');
    const analyticsController = new AnalyticsController({
      opts,
      analyticsStore,
      connectionAPIController,
      directorySyncController,
    });
    await analyticsController.init();
  }

  if ('driver' in opts.db) {
    logger.info(`Using external database driver`);
  } else {
    const type = opts.db.engine === 'sql' && opts.db.type ? ' Type: ' + opts.db.type : '';
    logger.info(`Using engine: ${opts.db.engine}.${type}`);
  }

  return {
    spConfig,
    apiController: connectionAPIController,
    connectionAPIController,
    oauthController,
    adminController,
    logoutController,
    setupLinkController,
    directorySyncController,
    oidcDiscoveryController,
    identityFederationController,
    brandingController,
    checkLicense: () => {
      return checkLicense(opts.boxyhqLicenseKey);
    },
    productController,
    close: async () => {
      await db.close();
    },
  };
};

export default controllers;

export * from './typings';
export * from './ee/identity-federation/types';
export type SAMLJackson = Awaited<ReturnType<typeof controllers>>;
export type ISetupLinkController = InstanceType<typeof SetupLinkController>;
export type IBrandingController = InstanceType<typeof BrandingController>;
