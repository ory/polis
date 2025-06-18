import { test as baseTest, expect } from '@playwright/test';
import { DSyncPage } from 'e2e/support/fixtures';
import { getDirectory } from 'e2e/api/helpers/directories';
import { options } from 'e2e/api/helpers/api';
import {
  addGroupMember,
  createGroup,
  createUser,
  deleteGroup,
  deleteUser,
  updateGroupName,
  updateUser,
} from 'e2e/api/helpers';
import {
  DirectorySyncProviders,
  azureGroup,
  azureUser,
  updatedAzureUser,
  oktaGroup,
  oktaUser,
  updatedOktaUser,
} from 'e2e/support/data/dsync';

type MyFixtures = {
  dsyncPage: DSyncPage;
};

export const test = baseTest.extend<MyFixtures>({
  dsyncPage: async ({ page }, use) => {
    const dsyncPage = new DSyncPage(page);
    // eslint-disable-next-line react-hooks/rules-of-hooks
    await use(dsyncPage);
    await dsyncPage.deleteConnection();
  },
});

test.use(options);

const providers = [
  { type: 'azure-scim-v2', generators: { user: azureUser, group: azureGroup, updateUser: updatedAzureUser } },
  { type: 'okta-scim-v2', generators: { user: oktaUser, group: oktaGroup, updateUser: updatedOktaUser } },
];

for (const provider of providers) {
  test(`${provider.type} SCIM connection`, async ({ dsyncPage, request, page, baseURL }) => {
    await dsyncPage.addDSyncConnection(provider.type as keyof typeof DirectorySyncProviders, baseURL!);
    //  Send API requests to user/groups endpoint
    const [directory] = await getDirectory(request, { tenant: dsyncPage.tenant, product: dsyncPage.product });
    const providerUser1 = provider.generators.user(1);
    const user1 = await createUser(request, directory, providerUser1);
    const group = await createGroup(request, directory, provider.generators.group);
    await addGroupMember(request, directory, group, user1.id);
    // Assert created user
    await dsyncPage.switchToDSyncInfoView();
    await dsyncPage.switchToUsersView({ waitForData: true });
    await expect(page.getByRole('cell', { name: providerUser1.name.givenName, exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: providerUser1.name.familyName, exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: providerUser1.emails[0].value, exact: true })).toBeVisible();
    // Assert created group
    await dsyncPage.switchToGroupsView({ waitForData: true });
    await expect(await page.getByRole('cell', { name: 'Ory' })).toBeVisible();
    // Enable webhook logs
    await dsyncPage.setWebHookEventsLogging({ enable: true, directory });
    const providerUser2 = provider.generators.user(2);
    const user2 = await createUser(request, directory, providerUser2);
    await addGroupMember(request, directory, group, user2.id);
    // Assert created user
    await dsyncPage.switchToDSyncInfoView();
    await dsyncPage.switchToUsersView({ waitForData: true });
    await expect(page.getByRole('cell', { name: providerUser2.name.givenName, exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: providerUser2.name.familyName, exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: providerUser2.emails[0].value, exact: true })).toBeVisible();
    // Patch second user
    const providerUser2Updated = provider.generators.updateUser(2);
    await updateUser(
      request,
      directory,
      user2.id,
      providerUser2Updated,
      providerUser2Updated.schemas[0] === 'urn:ietf:params:scim:api:messages:2.0:PatchOp'
    );
    await page.reload();
    // Assert updated attributes for user
    const { givenName, familyName, email } =
      'Operations' in providerUser2Updated
        ? {
            givenName: providerUser2Updated.Operations[0].value,
            familyName: providerUser2Updated.Operations[1].value,
            email: providerUser2Updated.Operations[2].value,
          }
        : {
            givenName: providerUser2Updated.name.givenName,
            familyName: providerUser2Updated.name.familyName,
            email: providerUser2Updated.emails[0].value,
          };
    await expect(
      page.getByRole('cell', {
        name: givenName,
        exact: true,
      })
    ).toBeVisible();
    await expect(page.getByRole('cell', { name: familyName, exact: true })).toBeVisible();
    await expect(page.getByRole('cell', { name: email, exact: true })).toBeVisible();
    // Assert webhook logs
    await dsyncPage.switchToEventsView({ waitForData: true });
    await dsyncPage.inspectEventRow(0, directory.webhook.endpoint);
    await expect(page.getByText('"user.updated"')).toBeVisible();
    await dsyncPage.switchToEventsView({ waitForData: true });
    await dsyncPage.inspectEventRow(1, directory.webhook.endpoint);
    await expect(page.getByText('"group.user_added"')).toBeVisible();
    await dsyncPage.switchToEventsView({ waitForData: true });
    await dsyncPage.inspectEventRow(2, directory.webhook.endpoint);
    await expect(page.getByText('"user.created"')).toBeVisible();
    // Delete webhook logs
    await dsyncPage.switchToEventsView();
    await page.getByRole('button', { name: 'Remove Events' }).click();
    await page.getByTestId('confirm-delete').click();
    await page.getByRole('table').waitFor({ state: 'detached' });
    await expect(
      page.getByRole('heading', { name: 'No webhook events found for this directory.' })
    ).toBeVisible();
    await dsyncPage.setWebHookEventsLogging({ enable: false, directory });
    // User deletion
    await deleteUser(request, directory, user1.id);
    await deleteUser(request, directory, user2.id);
    await dsyncPage.switchToDSyncInfoView();
    await dsyncPage.switchToUsersView();
    await expect(page.getByRole('heading', { name: 'No users found for this directory.' })).toBeVisible();
    await updateGroupName(request, directory, group.id, 'Ory-updated');
    await dsyncPage.switchToGroupsView({ waitForData: true });
    await expect(page.getByRole('cell', { name: 'Ory-updated' })).toBeVisible();
    // Group deletion
    await deleteGroup(request, directory, group.id);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'No groups found for this directory.' })).toBeVisible();
    await dsyncPage.switchToEventsView();
    await expect(
      page.getByRole('heading', { name: 'No webhook events found for this directory.' })
    ).toBeVisible();
  });
}
