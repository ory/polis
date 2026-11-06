import { test, expect } from '@playwright/test';
import { createDirectory, deleteDirectory, directoryPayload, getDirectory } from '../../helpers/directories';
import groups from '@boxyhq/saml-jackson/test/dsync/data/groups';
import { addGroupMember, createGroup, getGroupsByDirectoryId } from '../../helpers/groups';
import { options } from '../../helpers/api';

test.use(options);

const { tenant, product } = { ...directoryPayload, tenant: 'api-boxyhq-3' };
const memberId = 'member1';

test.beforeAll(async ({ request }) => {
  const directory = await createDirectory(request, {
    ...directoryPayload,
    tenant,
  });

  const group = await createGroup(request, directory, groups[0]);
  await addGroupMember(request, directory, group, memberId);
});

test.afterAll(async ({ request }) => {
  const [directory] = await getDirectory(request, { tenant, product });

  await deleteDirectory(request, directory.id);
});

test.describe('GET /api/v1/dsync/groups/:id/members', () => {
  test('should be able to get a group members from a directory', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });

    const groups = await getGroupsByDirectoryId(request, directory);
    const response = await request.get(`/api/v1/dsync/groups/${groups[0].id}/members`, {
      params: {
        tenant,
        product,
      },
    });

    const { data: directoryMembers } = await response.json();

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(directoryMembers.length).toBe(1);
    expect(directoryMembers).toMatchObject([
      {
        user_id: memberId,
      },
    ]);
  });
});
