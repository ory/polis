import { jacksonOptions } from '@lib/env';
import { test as baseTest, expect, request } from '@playwright/test';
import { waitForErrorPage } from 'e2e/api/helpers/utils';
import { ADMIN_PORTAL_PRODUCT, GENERIC_ERR_STRING, Portal, SSOPage } from 'e2e/support/fixtures';

type MyFixtures = {
  ssoPage: SSOPage;
  portal: Portal;
};

export const test = baseTest.extend<MyFixtures>({
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
  ssoPage: async ({ page, portal }, use) => {
    const ssoPage = new SSOPage(page);
    await ssoPage.goto();
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(ssoPage);
    await portal.doCredentialsLogin();
    await portal.isLoggedIn();
    await ssoPage.deleteAllSSOConnections();
  },
});

test.afterAll(async () => {
  const apiContext = await request.newContext();
  await apiContext.delete(`/api/v1/sso-traces/product?product=${ADMIN_PORTAL_PRODUCT}`, {
    headers: { Authorization: 'Api-Key secret' },
  });
});

const errorMessages: string[] = [];

test('OAuth2 wrapper + SAML provider + wrong redirectUrl', async ({ ssoPage, page, baseURL }, testInfo) => {
  const ssoName = `saml-${testInfo.workerIndex}`;
  await ssoPage.addSSOConnection({ name: ssoName, type: 'saml', baseURL: baseURL! });
  // check if the first added connection appears in the connection list
  await expect(page.getByText(`${ssoName}-1`)).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: `${ssoName}-1`,
    url: 'https://invalid-url.com',
  });
  // Logout of magic link login
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText('Redirect URL is not allowed.')).toBeVisible();
  errorMessages.push('Redirect URL is not allowed.');
});

test('OAuth2 wrapper + SAML provider + inactive connection', async ({ ssoPage, page, baseURL }, testInfo) => {
  const ssoName = `saml-${testInfo.workerIndex}`;
  await ssoPage.addSSOConnection({ name: ssoName, type: 'saml', baseURL: baseURL! });
  // check if the first added connection appears in the connection list
  await expect(page.getByText(`${ssoName}-1`)).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: `${ssoName}-1`,
    url: baseURL!,
    newStatus: false,
  });
  // Confirm connection label inactive is displayed
  await expect(
    page.getByText(`${ssoName}-1`).locator('xpath=..').getByRole('cell', { name: 'Inactive', exact: true })
  ).toBeVisible();
  // Logout and try to sign in with connection
  // Logout of magic link login
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText(GENERIC_ERR_STRING)).toBeVisible();
  errorMessages.push('SSO connection is deactivated.');
});

test('OAuth2 wrapper + OIDC provider + wrong redirectUrl', async ({ ssoPage, page, baseURL }, testInfo) => {
  const ssoName = `oidc-${testInfo.workerIndex}`;
  await ssoPage.addSSOConnection({ name: ssoName, type: 'oidc', baseURL: baseURL! });
  // check if the oidc connection appears in the connection list
  await expect(page.getByText(`${ssoName}-1`)).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: `${ssoName}-1`,
    url: 'https://invalid-url.com',
  });
  // Logout of magic link login
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText('Redirect URL is not allowed.')).toBeVisible();
  errorMessages.push('Redirect URL is not allowed.');
});

test('OAuth2 wrapper + OIDC provider + inactive connection', async ({ ssoPage, page, baseURL }, testInfo) => {
  const ssoName = `oidc-${testInfo.workerIndex}`;
  await ssoPage.addSSOConnection({ name: ssoName, type: 'oidc', baseURL: baseURL! });
  // check if the oidc connection appears in the connection list
  await expect(page.getByText(`${ssoName}-1`)).toBeVisible();
  await ssoPage.updateSSOConnection({
    name: `${ssoName}-1`,
    url: baseURL!,
    newStatus: false,
  });
  // Confirm connection label inactive is displayed
  await expect(
    page.getByText(`${ssoName}-1`).locator('xpath=..').getByRole('cell', { name: 'Inactive', exact: true })
  ).toBeVisible();
  // Logout and try to sign in with connection
  // Logout of magic link login
  await ssoPage.logout();
  await ssoPage.signInWithSSO();
  // Wait for browser to redirect to error page
  await waitForErrorPage(page, baseURL!, jacksonOptions.jsonErrorPage);
  // Assert error text
  await expect(page.getByText(GENERIC_ERR_STRING)).toBeVisible();
  errorMessages.push('SSO connection is deactivated.');
});

test('SSO Tracer inspect', async ({ page }) => {
  await page.goto('/');
  const responsePromise = page.waitForResponse('/api/admin/sso-traces?pageOffset=0&pageLimit=50');
  await page.getByRole('link', { name: 'SSO Traces' }).click();
  const response = await responsePromise;
  const traces = (await response.json()).data;
  for (let i = 0; i < errorMessages.length; i++) {
    await page.getByRole('cell').getByRole('button', { name: traces[i].traceId }).click();
    await expect(page.getByLabel('SP Protocol')).toContainText('OAuth 2.0');
    await expect(page.locator('dl')).toContainText(errorMessages[errorMessages.length - i - 1]);
    await page.getByRole('link', { name: 'Back' }).click();
  }
});
