import { Page, expect } from '@playwright/test';

const TEST_SETUPLINK_ADMIN_URL = '/admin/directory-sync/setup-link';
const TEST_SETUPLINK_URL_LABEL_SELECTOR =
  'Share this link with your customers to allow them to set up the integrationClose';

export class SetupLinkDSPage {
  setupLinkUrl: string;
  constructor(
    public readonly page: Page,
    public readonly product: string,
    public readonly tenant: string,
    public readonly adminPage: string = TEST_SETUPLINK_ADMIN_URL
  ) {
    this.page = page;
    this.product = product;
    this.tenant = tenant;
    this.adminPage = adminPage;
    this.setupLinkUrl = '';
  }

  async createSetupLink(baseURL: string) {
    // Create setup link
    await this.page.goto(this.adminPage);
    await this.page.getByRole('button', { name: 'New Setup Link' }).click();
    await this.page.getByPlaceholder('Acme Directory').fill('acme-test');
    await this.page.getByPlaceholder('acme', { exact: true }).fill(this.tenant);
    await this.page.getByPlaceholder('MyApp').fill(this.product);
    await this.page.getByPlaceholder('https://yourapp.com/webhook').fill(`${baseURL}/api/hello`);
    await this.page.getByPlaceholder('your-secret').fill('secret');
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
