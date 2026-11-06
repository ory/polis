import { expect, test as baseTest } from '@playwright/test';
import { Portal } from 'e2e/support/fixtures';

type MyFixtures = {
  portal: Portal;
};

export const test = baseTest.extend<MyFixtures>({
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    await page.goto('/admin');
    if (!(await portal.isLoggedInSoft())) {
      await portal.doCredentialsLogin();
      await portal.isLoggedIn();
    }
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
});

test.describe('Admin Portal Login callback URL validation', () => {
  test('should not redirect to a javascript: URL', async ({ portal }) => {
    // Track if any JavaScript dialog (alert/confirm/prompt) fires
    let dialogFired = false;
    portal.page.on('dialog', async (dialog) => {
      dialogFired = true;
      await dialog.dismiss();
    });

    await portal.page.goto('/admin/auth/login?callbackUrl=javascript:alert(1)');
    await portal.isLoggedIn();

    // The javascript: URL must not execute
    expect(dialogFired).toBe(false);

    // The page should not be on a javascript: URL
    expect(portal.page.url()).not.toContain('javascript:alert');
  });

  test('should not redirect to an external URL', async ({ portal }) => {
    await portal.page.goto('/admin/auth/login?callbackUrl=https://evil.example.com');
    await portal.isLoggedIn();

    // The page should remain on the local origin
    const currentUrl = new URL(portal.page.url());
    expect(currentUrl.hostname).toBe('localhost');
  });

  test('should redirect to a valid internal path', async ({ portal }) => {
    await portal.page.goto('/admin/auth/login?callbackUrl=/admin/sso-connection');
    await portal.isLoggedIn();

    expect(portal.page.url()).toContain('/admin/sso-connection');
  });
});
