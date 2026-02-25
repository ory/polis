import { expect, test as baseTest, Page } from '@playwright/test';
import { Portal, SetupLinkPage } from 'e2e/support/fixtures';

const TEST_SETUPLINK_MOCKSAML_ORIGIN = process.env.MOCKSAML_ORIGIN || 'https://mocksaml.com';
const TEST_SETUPLINK_MOCK_METADATA_URL = `${TEST_SETUPLINK_MOCKSAML_ORIGIN}/api/saml/metadata`;

const TEST_SETUPLINK_ADMIN_CONNECTION = '/admin/sso-connection';
const TENANT = 'acme-setuplink-test.com';
const PRODUCT = 'acme-setuplink-test';

type MyFixtures = {
  portal: Portal;
  setuplinkPage: SetupLinkPage;
};

export const test = baseTest.extend<MyFixtures>({
  portal: async ({ page }, use) => {
    const portal = new Portal(page);
    await portal.doCredentialsLogin();
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(portal);
  },
  setuplinkPage: async ({ page }, use) => {
    const setuplinkPage = new SetupLinkPage(page, PRODUCT, TENANT);

    // Create setup link
    await setuplinkPage.createSetupLink();

    // use setup link in all tests
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(setuplinkPage);

    // remove setup link
    await setuplinkPage.removeSetupLink();
  },
});

const setupLinkTestsData: {
  testDescription: string;
  testTitle: string;
  testRunner: (setupLinkPage: Page) => Promise<void>;
}[] = [
  {
    testDescription: 'Admin Portal Enterprise SSO SetupLink using generic SAML 2.0',
    testTitle: 'should be able to create setup link and sso connection using generic SAML 2.0',
    testRunner: testGenericSaml,
  },
  {
    testDescription: 'Admin Portal Enterprise SSO SetupLink using PingOne SAML 2.0',
    testTitle: 'should be able to create setup link and sso connection using PingOne SAML 2.0',
    testRunner: testPingOneSaml,
  },
  {
    testDescription: 'Admin Portal Enterprise SSO SetupLink using Okta SAML',
    testTitle: 'should be able to create setup link and sso connection using Okta SAML',
    testRunner: testOktaSaml,
  },
  {
    testDescription: 'Admin Portal Enterprise SSO SetupLink using Entra ID SAML SSO',
    testTitle: 'should be able to create setup link and sso connection Entra ID SAML SSO',
    testRunner: testAzureSaml,
  },
];

setupLinkTestsData.forEach((testData) => {
  test.describe(testData.testDescription, () => {
    test(testData.testTitle, async ({ page, setuplinkPage }) => {
      // get setuplink url
      const linkContent = await setuplinkPage.getSetupLinkUrl();

      // Open new tab and go to setup link page
      const context = page.context();
      const setupLinkPage = await context.newPage();
      await setupLinkPage.goto(linkContent);

      // run generic saml 2.0 test
      await testData.testRunner(setupLinkPage);

      await setupLinkPage.waitForURL(/\/setup\/.+\/sso-connection$/);
      await expect(setupLinkPage.getByRole('cell', { name: 'saml.example.com' })).toBeVisible();
      await setupLinkPage.close();

      // Go to connections page
      await page.goto(TEST_SETUPLINK_ADMIN_CONNECTION);

      // Check if new SSO connection is created
      await expect(
        page.getByText(TENANT, { exact: true }),
        'Failed to create new sso connection from setup-link'
      ).toBeVisible();
      await expect(
        page.getByText(PRODUCT, { exact: true }),
        'Failed to create new sso connection from setup-link'
      ).toBeVisible();

      // Delete the SSO connection
      await page.getByRole('row', { name: TENANT }).getByLabel('Edit').click();
      await page.getByRole('button', { name: 'Delete' }).click();
      await page.getByRole('button', { name: 'Confirm' }).click();
    });
  });
});

async function testGenericSaml(setupLinkPage: Page) {
  // Create SSO connection using generic SAML 2.0 workflow
  await setupLinkPage.getByRole('button', { name: 'Generic SAML 2.0' }).click();

  // check mdx generated content using remart-gfm plugin for step1
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 1: Configuration SAML' })).toBeVisible();
  await expect(setupLinkPage.getByText('Your Identity Provider (IdP)')).toHaveText(
    'Your Identity Provider (IdP) will ask for the following information while configuring the SAML application.'
  );

  await expect(setupLinkPage.getByText('Please do not add a trailing')).toHaveText(
    'Please do not add a trailing slash at the end of the URLs.'
  );

  await expect(setupLinkPage.getByText('Create them exactly as shown')).toHaveText(
    'Create them exactly as shown below:'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step2
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 2: SAML Profile/Claims/' })).toBeVisible();
  await expect(setupLinkPage.getByText('We try and support 4')).toHaveText(
    'We try and support 4 attributes in the SAML claims:'
  );

  await expect(setupLinkPage.getByText('This is how the common SAML')).toHaveText(
    'This is how the common SAML attributes map over for most providers, but some providers have custom mappings. Please refer to the documentation on the Identity Provider to understand the exact mapping.'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step3
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 3: Create SAML Connection' })).toBeVisible();

  await expect(setupLinkPage.getByText('Enter the Identity Provider')).toHaveText(
    'Enter the Identity Provider Metadata below. You can either enter the metadata URL or paste the XML file content directly.'
  );

  await setupLinkPage.getByPlaceholder('Paste the Metadata URL here').fill(TEST_SETUPLINK_MOCK_METADATA_URL);
  await setupLinkPage.getByRole('button', { name: 'Save' }).click();
}

async function testPingOneSaml(setupLinkPage: Page) {
  // Create SSO connection using PingOne SAML 2.0 workflow
  await setupLinkPage.getByRole('button', { name: 'PingOne SAML SSO' }).click();

  // check mdx generated content using remart-gfm plugin for step1
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 1: Create Application' })).toBeVisible();

  await expect(setupLinkPage.getByText('From your PingOne account,')).toHaveText(
    'From your PingOne account, click Connections > Applications from left navigation menu.'
  );

  await expect(setupLinkPage.getByText('If your application is')).toHaveText(
    'If your application is already created, choose it from the list and move to the next step.'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' })).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/pingone/1.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step2
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 2: Configure Application' })).toBeVisible();
  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/pingone/2.png'
  );

  await expect(setupLinkPage.getByText('From the next screen, you')).toHaveText(
    'From the next screen, you have to enter the following values in the SAML Configuration section:'
  );

  await expect(setupLinkPage.getByText('Click Save to save the')).toHaveText(
    'Click Save to save the configuration.'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step3
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 3: Attribute Mapping' })).toBeVisible();

  await expect(setupLinkPage.getByText('Click the Attribute Mappings')).toHaveText(
    'Click the Attribute Mappings tab from the top and you have to configure the following attributes:'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/pingone/5.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step4
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 4: Create SAML Connection' })).toBeVisible();

  await setupLinkPage.getByPlaceholder('Paste the Metadata URL here').fill(TEST_SETUPLINK_MOCK_METADATA_URL);
  await setupLinkPage.getByRole('button', { name: 'Save' }).click();
}

async function testOktaSaml(setupLinkPage: Page) {
  // Create SSO connection using Okta SAML  workflow
  await setupLinkPage.getByRole('button', { name: 'Okta SAML SSO' }).click();

  // check mdx generated content using remart-gfm plugin for step1
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 1: Create Application' })).toBeVisible();
  await expect(setupLinkPage.getByText('From your Okta account, click')).toHaveText(
    'From your Okta account, click Applications from the left navigation menu.'
  );

  await expect(setupLinkPage.getByText('If your application is')).toHaveText(
    'If your application is already created, choose it from the list and move to the next step.'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/1.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(1)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/2.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(2)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/3.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step2
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 2: Configure Application' })).toBeVisible();

  await expect(setupLinkPage.getByText('Enter the following values in')).toHaveText(
    'Enter the following values in the SAML Settings section on the next screen:'
  );

  await expect(setupLinkPage.getByText('Select EmailAddress from the')).toHaveText(
    'Select EmailAddress from the Name ID format dropdown.'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' })).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/4.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step3
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 3: Attribute Mapping' })).toBeVisible();

  await expect(setupLinkPage.getByText('Under the Attribute')).toHaveText(
    'Under the Attribute Statements section, you have to configure the following attributes:'
  );

  await expect(setupLinkPage.getByText('From your application, click')).toHaveText(
    'From your application, click Sign On tab and go to the section SAML Signing Certificates'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/5.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(1)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/6.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(2)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/okta/7.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step4
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 4: Create SAML Connection' })).toBeVisible();
  await expect(setupLinkPage.getByText('Enter the Identity Provider')).toHaveText(
    'Enter the Identity Provider Metadata below. You can either enter the metadata URL or paste the XML file content directly.'
  );

  await setupLinkPage.getByPlaceholder('Paste the Metadata URL here').fill(TEST_SETUPLINK_MOCK_METADATA_URL);
  await setupLinkPage.getByRole('button', { name: 'Save' }).click();
}

async function testAzureSaml(setupLinkPage: Page) {
  // Create SSO connection using Okta SAML  workflow
  await setupLinkPage.getByRole('button', { name: 'Entra ID SAML SSO' }).click();

  // check mdx generated content using remart-gfm plugin for step1
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 1: Create Application' })).toBeVisible();
  await expect(setupLinkPage.getByText('From your Azure Admin console')).toHaveText(
    'From your Azure Admin console, click Enterprise applications from the left navigation menu.'
  );

  await expect(setupLinkPage.getByText('If your application is')).toHaveText(
    'If your application is already created, choose it from the list and move to the next step.'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/1.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(1)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/2.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(2)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/3.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step2
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 2: Configure Application' })).toBeVisible();

  await expect(setupLinkPage.getByText('Enter the following values in')).toHaveText(
    'Enter the following values in the Basic SAML Configuration section on the next screen:'
  );

  await expect(setupLinkPage.getByText('Select Single Sign On from')).toHaveText(
    'Select Single Sign On from the Manage section of your app and then SAML.'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/4.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(1)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/5.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(2)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/6.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step3
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 3: Attribute Mapping' })).toBeVisible();

  await expect(setupLinkPage.getByText('Click Edit on the Attributes')).toHaveText(
    'Click Edit on the Attributes & Claims section.'
  );

  await expect(setupLinkPage.getByText('You have to configure the')).toHaveText(
    'You have to configure the following attributes under the Attributes & Claims section:'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).first()).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/7.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(1)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/8.png'
  );

  await expect(setupLinkPage.getByRole('img', { name: 'img alt' }).nth(2)).toHaveAttribute(
    'src',
    'https://cdn.boxyhq.com/docs/sso/providers/azure/9.png'
  );

  await setupLinkPage.getByRole('button', { name: 'Next Step' }).click();

  // check mdx generated content using remart-gfm plugin for step4
  await expect(setupLinkPage.getByRole('heading', { name: 'Step 4: Create SAML Connection' })).toBeVisible();
  await expect(setupLinkPage.getByText('Enter the Identity Provider')).toHaveText(
    'Enter the Identity Provider Metadata below. You can either enter the metadata URL or paste the XML file content directly.'
  );

  await setupLinkPage.getByPlaceholder('Paste the Metadata URL here').fill(TEST_SETUPLINK_MOCK_METADATA_URL);
  await setupLinkPage.getByRole('button', { name: 'Save' }).click();
}
