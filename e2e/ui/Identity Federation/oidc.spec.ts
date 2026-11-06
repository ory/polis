import { test as baseTest } from '@playwright/test';
import { Portal, SSOPage } from 'e2e/support/fixtures';
import { IdentityFederationPage } from 'e2e/support/fixtures/identity-federation';

type MyFixtures = {
  ssoPage: SSOPage;
  portal: Portal;
  oidcFedPage: IdentityFederationPage;
};

const test = baseTest.extend<MyFixtures>({
  ssoPage: async ({ page }, use) => {
    const ssoPage = new SSOPage(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(ssoPage);
    // Delete SSO Connections mapped to OIDC federation
    await ssoPage.deleteSSOConnection('SSO-via-OIDC-Fed');
    await ssoPage.deleteAllSSOConnections();
  },
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
  oidcFedPage: async ({ baseURL, page, portal }, use) => {
    const oidcFedPage = new IdentityFederationPage(page);
    // Create OIDC Federated connection
    await page.goto('/');
    const { oidcClientId, oidcClientSecret } = await oidcFedPage.createApp({
      type: 'oidc',
      baseURL: baseURL!,
      params: { name: 'OF-1' },
    });
    // Add OIDC Connection via OIDC Fed for Admin portal
    await portal.addSSOConnection({
      name: 'SSO-via-OIDC-Fed',
      type: 'oidc',
      oidcClientId,
      oidcClientSecret,
      oidcDiscoveryUrl: `${baseURL}/.well-known/openid-configuration`,
    });

    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(oidcFedPage);
    // Cleanup OIDC Fed app
    await oidcFedPage.deleteApp();
  },
});

test('OIDC Federated app + 1 SAML & 1 OIDC providers', async ({ baseURL, oidcFedPage, portal, ssoPage }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'OF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  await ssoPage.addSSOConnection({
    name: 'OF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  // Login using MockSAML
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('OF-SAML-1');
  await ssoPage.signInWithMockSAML();
  await portal.isLoggedIn();
  // Login using MockLab
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('OF-OIDC-2');
  await ssoPage.signInWithMockLab();
  await portal.isLoggedIn();
});

test('OIDC Federated app + 2 SAML providers', async ({ baseURL, oidcFedPage, ssoPage, portal }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'OF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  await ssoPage.addSSOConnection({
    name: 'OF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });

  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('OF-SAML-1');
  await ssoPage.signInWithMockSAML();
  await portal.isLoggedIn();
  // Login using MockSAML-2
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('OF-SAML-2');
  await ssoPage.signInWithMockSAML();
  await portal.isLoggedIn();
});

test('OIDC Federated app + 2 OIDC providers', async ({ baseURL, oidcFedPage, ssoPage, portal }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'OF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  await ssoPage.addSSOConnection({
    name: 'OF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });

  // Login using MockLab-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('OF-OIDC-1');
  await ssoPage.signInWithMockLab();
  await portal.isLoggedIn();
  // Login using MockLab-2
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('OF-OIDC-2');
  await ssoPage.signInWithMockLab();
  await portal.isLoggedIn();
});

test('OIDC Federated app + 1 SAML provider', async ({ baseURL, oidcFedPage, ssoPage, page, portal }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'OF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.signInWithMockSAML();
  // Wait for browser to redirect back to admin portal
  await page.waitForURL((url) => url.origin === baseURL);
  await portal.isLoggedIn();
});

test('OIDC Federated app + 1 OIDC provider', async ({ baseURL, oidcFedPage, ssoPage, page, portal }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'OF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  // Login using MockLab-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.signInWithMockLab();
  // Wait for browser to redirect back to admin portal
  await page.waitForURL((url) => url.origin === baseURL);
  await portal.isLoggedIn();
});
