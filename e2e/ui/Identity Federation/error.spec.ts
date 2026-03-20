import { jacksonOptions } from '@lib/env';
import { test as baseTest, expect, request } from '@playwright/test';
import { waitForErrorPage } from 'e2e/api/helpers/utils';
import { ADMIN_PORTAL_PRODUCT, GENERIC_ERR_STRING, Portal, SSOPage } from 'e2e/support/fixtures';
import { IdentityFederationPage } from 'e2e/support/fixtures/identity-federation';

type MyFixtures = {
  ssoPage: SSOPage;
  portal: Portal;
  samlFedPage: IdentityFederationPage;
  oidcFedPage: IdentityFederationPage;
};

const test = baseTest.extend<MyFixtures>({
  ssoPage: async ({ page }, use) => {
    const ssoPage = new SSOPage(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(ssoPage);
    // Delete SSO Connections mapped to Id federation
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
    await samlFedPage.createApp({
      baseURL: baseURL!,
      params: { name: 'SF-1' },
    });

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
  oidcFedPage: async ({ baseURL, page, portal }, use) => {
    const oidcFedPage = new IdentityFederationPage(page);
    // Create OIDC Federated connection
    await page.goto('/');
    const { oidcClientId, oidcClientSecret } = await oidcFedPage.createApp({
      type: 'oidc',
      baseURL: baseURL!,
      params: { name: 'OF-1', redirectUrl: 'https://invalid-url.com' },
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
    // Delete OIDC Fed connection
    await oidcFedPage.deleteApp();
  },
});

test.afterAll(async () => {
  const apiContext = await request.newContext();
  await apiContext.delete(`/api/v1/sso-traces/product?product=${ADMIN_PORTAL_PRODUCT}`, {
    headers: { Authorization: 'Api-Key secret' },
  });
});

const errorMessages: string[] = [];

test('SAML Federated app + Wrong ACS url', async ({ baseURL, page, portal, samlFedPage, ssoPage }) => {
  await samlFedPage.updateApp({ acsUrl: 'https://invalid-url.com' });
  // Add SSO connection for tenant
  await ssoPage.goto();
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
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText(GENERIC_ERR_STRING)).toBeVisible();

  errorMessages.push("Assertion Consumer Service URL doesn't match.");
  await portal.doCredentialsLogin();
  await portal.isLoggedIn();

  await ssoPage.deleteSSOConnection('SSO-via-SAML-Fed');
});

test('SAML Federated app + inactive SSO connection', async ({
  baseURL,
  page,
  portal,
  samlFedPage,
  ssoPage,
}) => {
  // Add SSO connection for tenants
  await ssoPage.goto();
  await ssoPage.addSSOConnection({
    name: 'SF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: samlFedPage.TENANT,
    product: samlFedPage.PRODUCT,
  });
  // check if the SAML connection appears in the connection list
  await expect(page.getByText('SF-SAML')).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: 'SF-SAML',
    url: baseURL!,
    newStatus: false,
  });
  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText(GENERIC_ERR_STRING)).toBeVisible();
  errorMessages.push('SSO connection is deactivated.');
  await portal.doCredentialsLogin();
  await portal.isLoggedIn();

  await ssoPage.deleteSSOConnection('SSO-via-SAML-Fed');
});

test('OIDC Federated app + SSO Provider with wrong redirect url', async ({
  baseURL,
  page,
  portal,
  ssoPage,
  oidcFedPage,
}) => {
  // Add SSO connection for tenants
  await ssoPage.goto();
  await ssoPage.addSSOConnection({
    name: 'OF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  // check if the SAML connection appears in the connection list
  await expect(page.getByText('OF-SAML')).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: 'OF-SAML',
    url: 'https://invalid-url.com',
  });
  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText('Redirect URL is not allowed.')).toBeVisible();
  errorMessages.push('Redirect URL is not allowed.');
  await portal.doCredentialsLogin();
  await portal.isLoggedIn();

  await ssoPage.deleteSSOConnection('SSO-via-OIDC-Fed');
});

test('OIDC Federated app + inactive SSO connection', async ({
  baseURL,
  page,
  portal,
  ssoPage,
  oidcFedPage,
}) => {
  // Add SSO connection for tenants
  await ssoPage.goto();
  await ssoPage.addSSOConnection({
    name: 'OF-SAML',
    type: 'saml',
    baseURL: baseURL!,
    tenant: oidcFedPage.TENANT,
    product: oidcFedPage.PRODUCT,
  });
  // check if the SAML connection appears in the connection list
  await expect(page.getByText('OF-SAML')).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: 'OF-SAML',
    url: baseURL!,
    newStatus: false,
  });
  // Login using MockSAML-1
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText(GENERIC_ERR_STRING)).toBeVisible();
  errorMessages.push('SSO connection is deactivated.');
  await portal.doCredentialsLogin();
  await portal.isLoggedIn();

  await ssoPage.deleteSSOConnection('SSO-via-OIDC-Fed');
});

test('SSO Tracer inspect', async ({ page }) => {
  await page.goto('/');
  const responsePromise = page.waitForResponse('/api/admin/sso-traces?pageOffset=0&pageLimit=50');
  await page.getByRole('link', { name: 'SSO Traces' }).click();
  const response = await responsePromise;
  const traces = (await response.json()).data;
  for (let i = 0; i < errorMessages.length; i++) {
    await page.getByRole('cell').getByRole('button', { name: traces[i].traceId }).click();
    await expect(page.getByLabel('SP Protocol')).toContainText(/OIDC Federation|SAML Federation/);
    await expect(page.locator('dl')).toContainText(errorMessages[errorMessages.length - i - 1]);
    await page.getByRole('link', { name: 'Back' }).click();
  }
});
