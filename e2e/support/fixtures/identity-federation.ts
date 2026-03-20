import { Locator, expect, type Page } from '@playwright/test';

export class IdentityFederationPage {
  public readonly TENANT = 'acme.com';
  public readonly PRODUCT = '_jackson_admin_portal';
  private readonly editButton: Locator;
  private readonly acsUrlInput: Locator;
  readonly ENTITY_ID = 'https://saml.boxyhq.com';
  constructor(public readonly page: Page) {
    this.editButton = this.page.getByRole('cell', { name: 'Edit' }).getByRole('button');
    this.acsUrlInput = this.page.getByLabel('ACS URL');
  }

  async goto() {
    await this.page.getByRole('link', { name: 'Apps' }).click();
  }

  async createApp({
    type = 'saml',
    baseURL,
    params: { name, acsUrl, entityID, redirectUrl } = { name: '' },
  }: {
    type?: 'oidc' | 'saml';
    baseURL: string;
    params: { name: string; acsUrl?: string; entityID?: string; redirectUrl?: string };
  }): Promise<any | { oidcClientId: string; oidcClientSecret: string }> {
    await this.goto();
    await this.page.waitForURL(/.*admin\/identity-federation$/);
    await this.page.getByRole('button', { name: 'New App' }).click();
    await this.page.waitForURL(/.*admin\/identity-federation\/new$/);
    if (type === 'oidc') {
      // Toggle connection type to OIDC
      await this.page.getByLabel('OIDC').check();
    }
    // Common config
    await this.page.getByPlaceholder('Your app').and(this.page.getByLabel('Name')).fill(name);
    await this.page.getByPlaceholder('example.com').and(this.page.getByLabel('Tenant')).fill(this.TENANT);
    await this.page.getByLabel('Product').fill(this.PRODUCT);

    if (type === 'saml') {
      await this.acsUrlInput.fill(acsUrl ?? `${baseURL}/api/oauth/saml`);
      await this.page
        .getByLabel('Entity ID / Audience URI / Audience Restriction')
        .fill(entityID ?? this.ENTITY_ID);
    } else {
      await this.page.locator('input[name="item"]').fill(redirectUrl ?? baseURL);
    }

    await this.page.getByRole('button', { name: 'Create App' }).click();
    await this.page.waitForURL(/.*admin\/identity-federation\/.*\/edit$/);

    let oidcClientId, oidcClientSecret;
    if (type === 'oidc') {
      oidcClientId = await this.page
        .locator('label')
        .filter({ hasText: 'Client ID' })
        .getByRole('textbox')
        .inputValue();
      oidcClientSecret = await this.page
        .locator('label')
        .filter({ hasText: 'Client Secret' })
        .getByRole('textbox')
        .inputValue();
    }

    await this.page.getByRole('link', { name: 'Back' }).click();
    await this.page.waitForURL(/.*admin\/identity-federation$/);
    await expect(this.page.getByRole('cell', { name })).toBeVisible();

    if (type === 'oidc') {
      return { oidcClientId, oidcClientSecret };
    }
  }

  async updateApp({ acsUrl }: { acsUrl?: string }) {
    await this.goto();
    await this.editButton.click();
    if (acsUrl) {
      await this.acsUrlInput.fill(acsUrl);
    }
    await this.page
      .locator('form')
      .filter({ hasText: 'NameTenantProductEntity ID /' })
      .getByRole('button', { name: 'Save Changes' })
      .first()
      .click();
  }

  async deleteApp() {
    await this.goto();
    await this.page.waitForURL(/.*admin\/identity-federation$/);
    await this.editButton.click();
    await this.page.locator('.card').getByRole('button', { name: 'Delete' }).click();
    await this.page.getByTestId('confirm-delete').click();
  }
}
