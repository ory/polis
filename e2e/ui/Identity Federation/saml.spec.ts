import { test as baseTest } from '@playwright/test';
import { Portal, SSOPage } from 'e2e/support/fixtures';
import { IdentityFederationPage } from 'e2e/support/fixtures/identity-federation';

type MyFixtures = {
  ssoPage: SSOPage;
  portal: Portal;
  samlFedPage: IdentityFederationPage;
};

const test = baseTest.extend<MyFixtures>({
  ssoPage: async ({ page }, use) => {
    const ssoPage = new SSOPage(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(ssoPage);
    // Delete SSO Connections mapped to SAML federation
    await ssoPage.deleteSSOConnection('SSO-via-SAML-Fed');
    await ssoPage.deleteAllSSOConnections();
  },
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
  samlFedPage: async ({ baseURL, page, portal }, use) => {
    const samlFedPage = new IdentityFederationPage(page);
    // Create SAML Federated connection
    await page.goto('/');
    await samlFedPage.createApp({ baseURL: baseURL!, params: { name: 'SF-1' } });
    // Add SAML connection via SAML Fed for Admin portal
    await portal.addSSOConnection({
      name: 'SSO-via-SAML-Fed',
      metadataUrl: `${baseURL}/.well-known/idp-metadata`,
    });

    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(samlFedPage);
    // Delete Saml Fed connection
    await samlFedPage.deleteApp();
  },
});

test('SAML Federated app + 1 SAML & 1 OIDC providers', async ({ baseURL, portal, samlFedPage, ssoPage }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'SF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  await ssoPage.addSSOConnection({
    name: 'SF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  // Login using MockSAML
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('SF-SAML-1');
  await ssoPage.signInWithMockSAML();
  await portal.isLoggedIn();
  // Login using MockLab
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('SF-OIDC-2');
  await ssoPage.signInWithMockLab();
  await portal.isLoggedIn();
});

test('SAML Federated app + 2 SAML providers', async ({ baseURL, portal, samlFedPage, ssoPage }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'SF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  await ssoPage.addSSOConnection({
    name: 'SF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });

  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('SF-SAML-1');
  await ssoPage.signInWithMockSAML();
  await portal.isLoggedIn();
  // Login using MockSAML-2
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('SF-SAML-2');
  await ssoPage.signInWithMockSAML();
  await portal.isLoggedIn();
});

test('SAML Federated app + 2 OIDC providers', async ({ baseURL, portal, samlFedPage, ssoPage }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'SF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  await ssoPage.addSSOConnection({
    name: 'SF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });

  // Login using MockLab-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('SF-OIDC-1');
  await ssoPage.signInWithMockLab();
  await portal.isLoggedIn();
  // Login using MockLab-2
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.selectIdP('SF-OIDC-2');
  await ssoPage.signInWithMockLab();
  await portal.isLoggedIn();
});

test('SAML Federated app + 1 SAML provider', async ({ baseURL, page, portal, samlFedPage, ssoPage }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'SF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.signInWithMockSAML();
  // Wait for browser to redirect back to admin portal
  await page.waitForURL((url) => url.origin === baseURL);
  await portal.isLoggedIn();
});

test('SAML Federated app + 1 OIDC provider', async ({ baseURL, page, portal, samlFedPage, ssoPage }) => {
  await ssoPage.goto();
  // Add SSO connection for tenants
  await ssoPage.addSSOConnection({
    name: 'SF-OIDC',
    type: 'oidc',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  // Login using MockLab-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  await ssoPage.signInWithMockLab();
  // Wait for browser to redirect back to admin portal
  await page.waitForURL((url) => url.origin === baseURL);
  await portal.isLoggedIn();
});
