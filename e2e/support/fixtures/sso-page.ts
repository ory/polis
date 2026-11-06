import { type Page, type Locator, expect } from '@playwright/test';
import { adminPortalSSODefaults } from '@lib/env';

export const GENERIC_ERR_STRING = 'Something wrong happened. Please contact your administrator.';

const ADMIN_PORTAL_TENANT = adminPortalSSODefaults.tenant;
export const ADMIN_PORTAL_PRODUCT = adminPortalSSODefaults.product;

const MOCKSAML_ORIGIN = process.env.MOCKSAML_ORIGIN || 'https://mocksaml.com';
const MOCKSAML_SIGNIN_BUTTON_NAME = 'Sign In';

const MOCKLAB_ORIGIN = 'https://oauth.wiremockapi.cloud';
const MOCKLAB_CLIENT_ID = 'mocklab_oauth2';
const MOCKLAB_CLIENT_SECRET = 'mocklab_secret';
const MOCKLAB_SIGNIN_BUTTON_NAME = 'Login';
const MOCKLAB_DISCOVERY_ENDPOINT = 'https://oauth.wiremockapi.cloud/.well-known/openid-configuration';

export class SSOPage {
  private readonly createConnection: Locator;
  private readonly nameInput: Locator;
  private readonly tenantInput: Locator;
  private readonly productInput: Locator;
  private readonly redirectURLSInput: Locator;
  private readonly defaultRedirectURLInput: Locator;
  private readonly metadataUrlInput: Locator;
  private readonly oidcDiscoveryUrlInput: Locator;
  private readonly oidcClientIdInput: Locator;
  private readonly oidcClientSecretInput: Locator;
  private readonly saveConnection: Locator;
  private readonly deleteButton: Locator;
  private readonly confirmButton: Locator;
  private readonly toggleConnectionStatusCheckbox: Locator;
  private readonly toggleConnectionStatusLabel: Locator;
  private connections: string[];

  constructor(public readonly page: Page) {
    this.connections = [];
    this.createConnection = this.page.getByTestId('create-connection');
    this.nameInput = this.page.getByLabel('Connection name (Optional)');
    this.tenantInput = this.page.getByLabel('Tenant');
    this.productInput = this.page.getByLabel('Product');
    this.redirectURLSInput = page
      .getByRole('group')
      .filter({ hasText: 'Allowed redirect URLs' })
      .locator(page.getByRole('textbox').first());
    this.defaultRedirectURLInput = this.page.getByLabel('Default redirect URL');
    this.metadataUrlInput = this.page.getByLabel('Metadata URL');
    this.oidcDiscoveryUrlInput = this.page.getByLabel('Well-known URL of OpenID Provider');
    this.oidcClientIdInput = this.page.getByLabel('Client ID');
    this.oidcClientSecretInput = this.page.getByLabel('Client Secret');
    this.saveConnection = this.page.getByRole('button', { name: /save/i });
    this.toggleConnectionStatusCheckbox = this.page.getByRole('checkbox', { name: 'Active' });
    this.toggleConnectionStatusLabel = this.page.locator('label').filter({ hasText: 'Active' });
    this.deleteButton = this.page.getByRole('button', { name: 'Delete' });
    this.confirmButton = this.page.getByRole('button', { name: 'Confirm' });
  }

  async goto() {
    const url = new URL(this.page.url());
    if (url.pathname !== '/admin/sso-connection') {
      await this.page.goto('/admin/sso-connection');
    }
  }

  async addSSOConnection({
    name,
    type = 'saml',
    tenant,
    product,
    baseURL,
  }: {
    name: string;
    type: 'saml' | 'oidc';
    tenant?: string;
    product?: string;
    baseURL: string;
  }) {
    const connectionIndex = this.connections.length + 1;
    const ssoName = `${name}-${connectionIndex}`;
    // Find the new connection button and click on it
    await this.createConnection.click();
    if (type === 'oidc') {
      // Toggle connection type to OIDC
      await this.page.getByLabel('OIDC').check();
    }
    // Fill the name for the connection
    await this.nameInput.fill(ssoName);
    // Fill the tenant for the connection
    await this.tenantInput.fill(tenant || ADMIN_PORTAL_TENANT);
    // Fill the product for the connection
    await this.productInput.fill(product || ADMIN_PORTAL_PRODUCT);
    // Fill the Allowed redirect URLs for the connection

    await this.redirectURLSInput.fill(baseURL!);
    // Fill the default redirect URLs for the connection
    await this.defaultRedirectURLInput.fill(`${baseURL}/admin/auth/idp-login`);
    if (type === 'saml') {
      // Enter the metadata url for mocksaml in the form
      await this.metadataUrlInput.fill(`${MOCKSAML_ORIGIN}/api/namespace/${ssoName}/saml/metadata`);
    }
    if (type === 'oidc') {
      // Enter the OIDC client credentials for mocklab in the form
      await this.oidcClientIdInput.fill(`${MOCKLAB_CLIENT_ID}-${connectionIndex}`);
      await this.oidcClientSecretInput.fill(`${MOCKLAB_CLIENT_SECRET}-${connectionIndex}`);
      // Enter the OIDC discovery url for mocklab in the form
      await this.oidcDiscoveryUrlInput.fill(MOCKLAB_DISCOVERY_ENDPOINT);
    }
    // submit the form
    await this.saveConnection.click();
    // check if the added connection appears in the connection list
    await expect(this.page.getByText(ssoName)).toBeVisible();
    this.connections = [...this.connections, ssoName];
  }

  async gotoEditView(name: string) {
    await this.goto();
    const editButton = this.page.getByText(name).locator('xpath=..').getByLabel('Edit');
    await editButton.click();
  }

  async toggleConnectionStatus(newStatus: boolean) {
    const isChecked = await this.toggleConnectionStatusCheckbox.isChecked();
    if (isChecked && !newStatus) {
      await this.toggleConnectionStatusLabel.click();
      await this.confirmButton.click();
    } else if (!isChecked && newStatus) {
      await this.toggleConnectionStatusLabel.click();
      await this.confirmButton.click();
    }
  }

  async updateSSOConnection({ name, url, newStatus }: { name: string; url: string; newStatus?: boolean }) {
    await this.gotoEditView(name);
    await this.redirectURLSInput.fill(url);
    await this.saveConnection.click();
    if (typeof newStatus === 'boolean') {
      await this.gotoEditView(name);
      await this.toggleConnectionStatus(newStatus);
    }
  }

  async deleteSSOConnection(name: string) {
    await this.gotoEditView(name);
    // click the delete and confirm deletion
    await this.deleteButton.click();
    await this.confirmButton.click();
    await expect(this.page.getByText('SSO Connection deleted successfully')).toBeVisible();
    // Adding this here as sometimes the toast intercepts pointer events, hence closing it manually
    await this.page.getByRole('alert').getByRole('button', { name: 'X' }).click();
  }

  async deleteAllSSOConnections() {
    let _connection;
    while ((_connection = this.connections.shift())) {
      await this.deleteSSOConnection(_connection);
    }
  }

  async logout() {
    const userAvatarLocator = this.page.getByTestId('user-avatar');
    // Logout from the magic link authentication
    await userAvatarLocator.click();
    await this.page.getByTestId('logout').click();
  }

  async signInWithSSO() {
    await this.page.getByTestId('sso-login-button').click();
  }

  async selectIdP(name: string) {
    const idpSelectionTitle = 'Select an Identity Provider to continue';
    await this.page.getByText(idpSelectionTitle).waitFor();
    await this.page.getByRole('button', { name }).click();
  }

  async signInWithMockSAML() {
    // Perform sign in at mocksaml
    await this.page.waitForURL((url) => url.origin === MOCKSAML_ORIGIN);
    await this.page.getByPlaceholder('jackson').fill('bob');
    await this.page.getByRole('button', { name: MOCKSAML_SIGNIN_BUTTON_NAME }).click();
  }

  async signInWithMockLab() {
    // Perform sign in at mocklab
    await this.page.waitForURL((url) => url.origin === MOCKLAB_ORIGIN);
    await this.page.getByPlaceholder('yours@example.com').fill('bob@oidc.com');
    await this.page.getByRole('button', { name: MOCKLAB_SIGNIN_BUTTON_NAME }).click();
  }
}
