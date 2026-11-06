import { test as baseTest, expect } from '@playwright/test';
import { Portal, SSOPage } from 'e2e/support/fixtures';

type MyFixtures = {
  ssoPage: SSOPage;
  portal: Portal;
};

export const test = baseTest.extend<MyFixtures>({
  ssoPage: async ({ page, baseURL }, use, testInfo) => {
    const ssoPage = new SSOPage(page);
    let ssoName = `saml-${testInfo.workerIndex}`;
    await ssoPage.goto();
    await ssoPage.addSSOConnection({ name: ssoName, type: 'saml', baseURL: baseURL! });
    await ssoPage.goto();
    ssoName = `oidc-${testInfo.workerIndex}`;
    await ssoPage.addSSOConnection({ name: ssoName, type: 'oidc', baseURL: baseURL! });
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(ssoPage);
    await ssoPage.deleteAllSSOConnections();
  },
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
});

test('OAuth2 wrapper + SAML provider + OIDC provider', async ({
  ssoPage,
  portal,
  page,
  baseURL,
}, testInfo) => {
  // check if the first added connection appears in the connection list
  await expect(page.getByText(`saml-${testInfo.workerIndex}-1`)).toBeVisible();
  // check if the second added connection appears in the connection list
  await expect(page.getByText(`oidc-${testInfo.workerIndex}-2`)).toBeVisible();
  // Logout of magic link login
  await ssoPage.logout();
  // Login using MockSAML
  await ssoPage.signInWithSSO();
  // Select IdP from selection screen
  await ssoPage.selectIdP(`saml-${testInfo.workerIndex}-1`);
  // Login using MockSAML
  await ssoPage.signInWithMockSAML();
  // Wait for browser to redirect back to admin portal
  await page.waitForURL((url) => url.origin === baseURL);
  // Assert logged in state
  await portal.isLoggedIn();

  // Logout of SAML login
  await ssoPage.logout();
  // Login using MockLab
  await ssoPage.signInWithSSO();
  // Select IdP from selection screen
  await ssoPage.selectIdP(`oidc-${testInfo.workerIndex}-2`);
  // Login using MockLab
  await ssoPage.signInWithMockLab();
  // Wait for browser to redirect back to admin portal
  await page.waitForURL((url) => url.origin === baseURL);
  // Assert logged in state
  await portal.isLoggedIn();
});
