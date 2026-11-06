import { SSO } from './sso';
import { App } from './app';
import type { JacksonOptionWithRequiredLogger, SSOTracesInstance } from '../../typings';
import { SSOHandler } from '../../controller/sso-handler';
import { IdPLogin } from './idp-login';

// This is the main entry point for the Identity Federation module
const IdentityFederation = async ({
  db,
  opts,
  ssoTraces,
}: {
  db;
  opts: JacksonOptionWithRequiredLogger;
  ssoTraces: SSOTracesInstance;
}) => {
  const appStore = db.store('samlfed:apps');
  const sessionStore = db.store('oauth:session', opts.db.ttl);
  const connectionStore = db.store('saml:config');

  const ssoHandler = new SSOHandler({
    connection: connectionStore,
    session: sessionStore,
    opts,
  });

  const app = new App({ store: appStore, opts });
  const sso = new SSO({ app, ssoHandler, ssoTraces, opts });
  const idpLogin = new IdPLogin({ app, ssoHandler, ssoTraces, opts });

  const response = {
    app,
    sso,
    idpLogin,
  };

  return response;
};

export default IdentityFederation;

export * from './types';

// SAML Federation flow:
// SP (Eg: Twilio Flex) --> Polis --> IdP (Eg: Okta) --> Polis --> SP (Eg: Twilio Flex)
// 1. SP send SAML Request to Jackson's SSO endpoint
// 2. Jackson process SAML Request and create a new session to store SP request information
// 3. Jackson create a new SAML Request and send it to chosen IdP
// 4. After successful authentication, IdP send (POST) SAML Response to Jackson's ACS endpoint
// 5. Jackson process SAML Response from the IdP and create a new SAML Response to send (POST) back to the SP's ACS endpoint
