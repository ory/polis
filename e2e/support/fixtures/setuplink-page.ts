import { Page, expect } from '@playwright/test';

const TEST_SETUPLINK_REDIRECT_URL = 'http://localhost:3366';
const TEST_SETUPLINK_DEFAULT_REDIRECT_URL = 'http://localhost:3366/login/saml';
const TEST_SETUPLINK_ADMIN_URL = '/admin/sso-connection/setup-link';
const TEST_SETUPLINK_URL_LABEL_SELECTOR =
  'Share this link with your customers to allow them to set up the integrationClose';

export class SetupLinkPage {
  setupLinkUrl: string;
  constructor(
    public readonly page: Page,
    public readonly product: string,
    public readonly tenant: string,
    public readonly adminPage: string = TEST_SETUPLINK_ADMIN_URL,
    public readonly redirectUrl: string = TEST_SETUPLINK_REDIRECT_URL,
    public readonly defaultRedirectUrl: string = TEST_SETUPLINK_DEFAULT_REDIRECT_URL
  ) {
    this.page = page;
    this.product = product;
    this.tenant = tenant;
    this.adminPage = adminPage;
    this.redirectUrl = redirectUrl;
    this.defaultRedirectUrl = defaultRedirectUrl;
    this.setupLinkUrl = '';
  }

  async createSetupLink() {
    // Go to admin/sso-connection/setup-link page and create setup link
    await this.page.goto(this.adminPage);
    await this.page.getByRole('button', { name: 'New Setup Link' }).click();
    await this.page.getByPlaceholder('Acme SSO').fill('acme-test');
    await this.page.getByLabel('Description (Optional)').fill('acme test');
    await this.page.getByPlaceholder('acme', { exact: true }).fill(this.tenant);
    await this.page.getByPlaceholder('MyApp').fill(this.product);
    await this.page.getByPlaceholder('http://localhost:3366', { exact: true }).fill(this.redirectUrl);
    await this.page.getByPlaceholder('http://localhost:3366/login/').fill(this.defaultRedirectUrl);

    await this.page.getByRole('button', { name: 'Create Setup Link' }).click();

    // Extract generated setup link
    this.setupLinkUrl = await this.page
      .getByText(TEST_SETUPLINK_URL_LABEL_SELECTOR)
      .locator('input[type="text"]')
      .first()
      .inputValue();
  }

  async getSetupLinkUrl(): Promise<string> {
    return this.setupLinkUrl;
  }

  async isSetupLinkCreated() {
    // Go back to new connections page
    await this.page.goto(TEST_SETUPLINK_ADMIN_URL);

    // Await for rows loaded
    await expect(this.page.getByRole('table')).toBeVisible();

    // Check if setup link is created
    await expect(
      this.page.getByText(this.tenant, { exact: true }),
      'Failed to create setup link'
    ).toBeVisible();
    await expect(
      this.page.getByText(this.product, { exact: true }),
      'Failed to create setup link'
    ).toBeVisible();
  }

  async removeSetupLink() {
    // Go back to setup link admin url
    await this.page.goto(TEST_SETUPLINK_ADMIN_URL);

    // Await for rows loaded
    await expect(this.page.getByRole('table')).toBeVisible();

    // Delete the created setuplink
    await this.page.getByRole('button').nth(5).click();
    await this.page.getByRole('button', { name: 'Delete' }).click();
  }
}
