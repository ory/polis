import { expect, test } from '@playwright/test';

// SAML SSO
const TEST_SAML_SSO_CONNECTION_NAME = 'pw_admin_portal_saml_sso';
const MOCKSAML_ORIGIN = process.env.MOCKSAML_ORIGIN || 'https://mocksaml.com';
const MOCKSAML_METADATA_URL = `${MOCKSAML_ORIGIN}/api/saml/metadata`;
const MOCKSAML_SIGNIN_BUTTON_NAME = 'Sign In';
// OIDC SSO
const TEST_OIDC_SSO_CONNECTION_NAME = 'pw_admin_portal_oidc_sso';
const MOCKLAB_DISCOVERY_ENDPOINT = 'https://oauth.wiremockapi.cloud/.well-known/openid-configuration';
const MOCKLAB_ISSUER = 'https://oauth.wiremockapi.cloud';
const MOCKLAB_AUTHORIZATION_ENDPOINT = 'https://oauth.wiremockapi.cloud/oauth/authorize';
const MOCKLAB_TOKEN_ENDPOINT = 'https://oauth.wiremockapi.cloud/oauth/token';
const MOCKLAB_USERINFO_ENDPOINT = 'https://oauth.wiremockapi.cloud/userinfo';
const MOCKLAB_JWKS_URI = 'https://oauth.wiremockapi.cloud/.well-known/jwks.json';
const MOCKLAB_ORIGIN = 'https://oauth.wiremockapi.cloud';
const MOCKLAB_CLIENT_ID = 'mocklab_oauth2';
const MOCKLAB_CLIENT_SECRET = 'mocklab_secret';
const MOCKLAB_SIGNIN_BUTTON_NAME = 'Login';

test.describe('Admin Portal SSO - SAML', () => {
  const samlMetadataMode = ['metadataUrl', 'rawMetadata'];
  for (const mode of samlMetadataMode) {
    test.describe(`SSO Connection via ${mode}`, () => {
      test('should be able to add SSO connection to mocksaml', async ({ page }) => {
        await page.goto('/admin/settings');
        // Find the new connection button and click on it
        await page.getByTestId('create-connection').click();
        // Fill the name for the connection
        const nameInput = page.getByLabel('Connection name (Optional)');
        await nameInput.fill(TEST_SAML_SSO_CONNECTION_NAME);
        if (mode === 'metadataUrl') {
          // Enter the metadata url for mocksaml in the form
          const metadataUrlInput = page.getByLabel('Metadata URL');
          await metadataUrlInput.fill(MOCKSAML_METADATA_URL);
        } else {
          // Enter the raw metadata
          const rawMetadataInput = page.getByLabel('Raw IdP XML');
          await rawMetadataInput.fill(process.env.MOCKSAML_METADATA!);
        }
        // submit the form
        await page.getByRole('button', { name: /save/i }).click();
        // check if the added connection appears in the connection list
        await expect(page.getByText(TEST_SAML_SSO_CONNECTION_NAME)).toBeVisible();
      });

      test('should be able to login with mocksaml via SP initiated SSO', async ({ page, baseURL }) => {
        const userAvatarLocator = page.getByTestId('user-avatar');
        // Logout from the magic link authentication
        await page.goto('/');
        await userAvatarLocator.click();
        await page.getByTestId('logout').click();
        // Click on login with sso button
        await page.getByTestId('sso-login-button').click();
        // Perform sign in at mocksaml
        await page.waitForURL((url) => url.origin === MOCKSAML_ORIGIN);
        await page.getByPlaceholder('jackson').fill('bob');
        await page.getByRole('button', { name: MOCKSAML_SIGNIN_BUTTON_NAME }).click();
        // Wait for browser to redirect back to admin portal
        await page.waitForURL((url) => url.origin === baseURL);
        // assert login state
        await expect(userAvatarLocator).toBeVisible();
      });

      test('should be able to login with mocksaml via IdP initiated SSO', async ({ page, baseURL }) => {
        const userAvatarLocator = page.getByTestId('user-avatar');
        // Logout from the magic link authentication
        await page.goto('/');
        await userAvatarLocator.click();
        await page.getByTestId('logout').click();
        await expect(page.getByTestId('sso-login-button')).toBeVisible();
        // Go directly to mocksaml hosting
        await page.goto(MOCKSAML_ORIGIN);
        await page.getByRole('link', { name: 'Test IdP Login' }).click();
        await page
          .getByPlaceholder('https://sso.eu.boxyhq.com/api/oauth/saml')
          .fill(`${baseURL}/api/oauth/saml`);
        await page.getByRole('textbox', { name: 'Please provide a mock email address' }).fill('bob');
        await page.getByRole('button', { name: MOCKSAML_SIGNIN_BUTTON_NAME }).click();
        // Wait for browser to redirect to admin portal
        await page.waitForURL((url) => url.origin === baseURL);
        // assert login state
        await expect(userAvatarLocator).toBeVisible();
      });

      test('delete the SAML SSO connection', async ({ page }) => {
        await page.goto('/admin/settings');
        // select the row of the connection list table, then locate the edit button
        const editButton = page
          .getByText(TEST_SAML_SSO_CONNECTION_NAME)
          .locator('xpath=..')
          .getByLabel('Edit');
        await editButton.click();
        // click the delete and confirm deletion
        await page.getByRole('button', { name: 'Delete' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        // check that the SSO connection is deleted from the connection list
        await expect(page.getByText(TEST_SAML_SSO_CONNECTION_NAME)).not.toBeVisible();
      });
    });
  }
});

test.describe('Admin Portal SSO - OIDC', () => {
  const oidcMetadataMode = ['discoveryUrl', 'metadata'];
  for (const mode of oidcMetadataMode) {
    test.describe(`SSO connection via ${mode}`, () => {
      test('should be able to add OIDC SSO connection to mocklab', async ({ page }) => {
        await page.goto('/admin/settings');
        // Find the new connection button and click on it
        await page.getByTestId('create-connection').click();
        // Toggle connection type to OIDC
        await page.getByLabel('OIDC').check();
        // Fill the name for the connection
        const nameInput = page.getByLabel('Connection name (Optional)');
        await nameInput.fill(TEST_OIDC_SSO_CONNECTION_NAME);
        if (mode === 'discoveryUrl') {
          // Enter the OIDC discovery url for mocklab in the form
          const discoveryUrlInput = page.getByLabel('Well-known URL of OpenID Provider');
          await discoveryUrlInput.fill(MOCKLAB_DISCOVERY_ENDPOINT);
        } else {
          // Enter the OIDC issuer value for mocklab in the form
          const issuerInput = page.getByLabel('issuer');
          await issuerInput.fill(MOCKLAB_ISSUER);
          // Enter the OIDC authorization_endpoint value for mocklab in the form
          const authzEndpointInput = page.getByLabel('Authorization Endpoint');
          await authzEndpointInput.fill(MOCKLAB_AUTHORIZATION_ENDPOINT);
          // Enter the OIDC token_endpoint value for mocklab in the form
          const tokenEndpointInput = page.getByLabel('Token endpoint');
          await tokenEndpointInput.fill(MOCKLAB_TOKEN_ENDPOINT);
          // Enter the OIDC userinfo_endpoint value for mocklab in the form
          const userInfoEndpointInput = page.getByLabel('UserInfo endpoint');
          await userInfoEndpointInput.fill(MOCKLAB_USERINFO_ENDPOINT);
          // Enter the OIDC jwks_uri value for mocklab in the form
          const jwksUriInput = page.getByLabel('JWKS URI');
          await jwksUriInput.fill(MOCKLAB_JWKS_URI);
        }
        // Enter the OIDC client credentials for mocklab in the form
        const clientIdInput = page.getByLabel('Client ID');
        await clientIdInput.fill(MOCKLAB_CLIENT_ID);
        const clientSecretInput = page.getByLabel('Client Secret');
        await clientSecretInput.fill(MOCKLAB_CLIENT_SECRET);
        // submit the form
        await page.getByRole('button', { name: /save/i }).click();
        // check if the added connection appears in the connection list
        await expect(page.getByText(TEST_OIDC_SSO_CONNECTION_NAME)).toBeVisible();
      });

      test('should be able to login with mocklab', async ({ page, baseURL }) => {
        const userAvatarLocator = page.getByTestId('user-avatar');
        // Logout from the magic link authentication
        await page.goto('/');
        await userAvatarLocator.click();
        await page.getByTestId('logout').click();
        // Click on login with sso button
        await page.getByTestId('sso-login-button').click();
        // Perform sign in at mocklab
        await page.waitForURL((url) => url.origin === MOCKLAB_ORIGIN);
        await page.getByPlaceholder('yours@example.com').fill('bob@oidc.com');
        await page.getByRole('button', { name: MOCKLAB_SIGNIN_BUTTON_NAME }).click();
        // Wait for browser to redirect back to admin portal
        await page.waitForURL((url) => url.origin === baseURL);
        // assert login state
        await expect(userAvatarLocator).toBeVisible();
      });

      test('delete the OIDC SSO connection', async ({ page }) => {
        await page.goto('/admin/settings');
        // select the row of the connection list table, then locate the edit button
        const editButton = page.getByText(TEST_OIDC_SSO_CONNECTION_NAME).locator('..').getByLabel('Edit');
        await editButton.click();
        // click the delete and confirm deletion
        await page.getByRole('button', { name: 'Delete' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        // check that the SSO connection is deleted from the connection list
        await expect(page.getByText(TEST_OIDC_SSO_CONNECTION_NAME)).not.toBeVisible();
      });
    });
  }
});
