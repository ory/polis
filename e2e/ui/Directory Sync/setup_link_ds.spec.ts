import { expect, test as baseTest, Page } from '@playwright/test';
import { Portal, SetupLinkDSPage } from 'e2e/support/fixtures';

const TENANT = 'acme-setuplink-test.com';
const PRODUCT = 'acme-setuplink-test';

type MyFixtures = {
  portal: Portal;
  setuplinkPage: SetupLinkDSPage;
};

export const test = baseTest.extend<MyFixtures>({
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    await portal.doCredentialsLogin();
    await portal.isLoggedIn;
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
  setuplinkPage: async ({ page, baseURL }, use) => {
    const setuplinkPage = new SetupLinkDSPage(page, PRODUCT, TENANT);

    // Create setup link
    await setuplinkPage.createSetupLink(baseURL!);

    // use setup link in all tests
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(setuplinkPage);

    // remove setup link
    await setuplinkPage.removeSetupLink();
  },
});

async function createDirectory(setupLinkPage: Page) {
  await setupLinkPage.getByRole('button', { name: 'Create Directory' }).click();
  await expect(setupLinkPage.getByLabel('SCIM Endpoint')).toBeVisible();
  await setupLinkPage.getByRole('link', { name: 'Back' }).click();
}

async function deleteDirectory(setupLinkPage: Page) {
  await setupLinkPage.getByLabel('Edit').click();
  await setupLinkPage.getByRole('button', { name: 'Delete' }).click();
  await setupLinkPage.getByRole('button', { name: 'Confirm' }).click();
}

test.describe('Admin Portal Dyrectory Sync SetupLink', () => {
  test('should be able to create setup link and directories', async ({ page, setuplinkPage }) => {
    // get setuplink url
    const linkContent = await setuplinkPage.getSetupLinkUrl();

    // Open new tab and go to setup link page
    const context = page.context();
    const setupLinkPage = await context.newPage();
    await setupLinkPage.goto(linkContent);

    // Create Entra ID SCIM v2.0 directory
    await expect(setupLinkPage.getByRole('heading', { name: 'Directory Sync' })).toBeVisible();
    await setupLinkPage.getByRole('link', { name: 'New Directory' }).click();
    await createDirectory(setupLinkPage);

    // Test if Entra ID SCIM v2.0 directory is created
    await expect(setupLinkPage.getByRole('cell', { name: 'Entra ID SCIM v2.0' })).toBeVisible();

    // Delete Entra ID SCIM v2.0 directory
    await deleteDirectory(setupLinkPage);

    // Create Generic SCIM v2.0 directory
    await setupLinkPage.getByRole('link', { name: 'New Directory' }).click();
    await setupLinkPage
      .locator('form div')
      .filter({ hasText: 'Directory providerEntra ID SCIM' })
      .locator('div')
      .click();
    await setupLinkPage.getByLabel('Directory provider').selectOption('generic-scim-v2');
    await createDirectory(setupLinkPage);

    // Test if Generic SCIM v2.0 directory is created
    await expect(setupLinkPage.getByRole('cell', { name: 'Generic SCIM v2.0' })).toBeVisible();

    // Delete AGeneric SCIM v2.0 directory
    await deleteDirectory(setupLinkPage);

    // Create Okta SCIM v2.0 directory
    await setupLinkPage.getByRole('link', { name: 'New Directory' }).click();
    await setupLinkPage
      .locator('form div')
      .filter({ hasText: 'Directory providerEntra ID SCIM' })
      .locator('div')
      .click();
    await setupLinkPage.getByLabel('Directory provider').selectOption('okta-scim-v2');
    await createDirectory(setupLinkPage);

    // Test if Okta SCIM v2.0 directory is created
    await expect(setupLinkPage.getByRole('cell', { name: 'Okta SCIM v2.0' })).toBeVisible();

    // Delete Okta SCIM v2.0 directory
    await deleteDirectory(setupLinkPage);

    await setupLinkPage.close();
  });
});
