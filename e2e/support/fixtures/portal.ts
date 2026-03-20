import { Locator, Page, expect } from '@playwright/test';

export class Portal {
  userAvatarLocator: Locator;
  constructor(public readonly page: Page) {
    this.userAvatarLocator = this.page.getByTestId('user-avatar');
  }

  async addSSOConnection({
    name,
    type = 'saml',
    metadataUrl,
    oidcDiscoveryUrl,
    oidcClientId,
    oidcClientSecret,
  }: {
    name: string;
    type?: 'saml' | 'oidc';
    metadataUrl?: string;
    oidcDiscoveryUrl?: string;
    oidcClientId?: string;
    oidcClientSecret?: string;
  }) {
    await this.page.getByRole('link', { name: 'Single Sign-On' }).click();
    await this.page.getByTestId('create-connection').click();
    if (type === 'oidc') {
      await this.page.getByLabel('OIDC').check();
    }
    await this.page.getByLabel('Connection name (Optional)').fill(name);
    if (type === 'saml') {
      await this.page.getByPlaceholder('Paste the Metadata URL here').fill(metadataUrl!);
    }
    if (type === 'oidc') {
      await this.page.getByLabel('Client ID').fill(oidcClientId!);
      await this.page.getByLabel('Client Secret').fill(oidcClientSecret!);
      await this.page.getByLabel('Well-known URL of OpenID Provider').fill(oidcDiscoveryUrl!);
    }
    await this.page.getByRole('button', { name: 'Save' }).click();
    await expect(this.page.getByRole('cell', { name })).toBeVisible();
  }

  async doCredentialsLogin() {
    await this.page.goto('/admin/auth/login');

    const email = await this.page.getByPlaceholder('Email');
    await email.waitFor({ state: 'visible', timeout: 20000 });
    await email.fill('super@boxyhq.com');

    await this.page.getByPlaceholder('Password').fill('999login');
    await this.page.getByRole('button', { name: 'Sign In' }).click();
  }

  async isLoggedIn() {
    // assert login state
    await expect(this.userAvatarLocator).toBeVisible();
  }

  async isLoggedInSoft(): Promise<boolean> {
    return this.userAvatarLocator.isVisible();
  }
}
