import { test, expect } from '@playwright/test';
import { createDirectory, deleteDirectory, directoryPayload, getDirectory } from '../../helpers/directories';
import { createUser, getUser } from '../../helpers/users';
import { createGroup, getGroupByDisplayName, getGroupById } from '../../helpers/groups';
import groups from '../../../../npm/test/dsync/data/groups';
import users from '../../../../npm/test/dsync/data/users';
import { options } from '../../helpers/api';

test.use(options);

const { tenant, product } = { ...directoryPayload, tenant: 'api-boxyhq-1' };

test.beforeAll(async ({ request }) => {
  await createDirectory(request, {
    ...directoryPayload,
    tenant,
  });
});

test.afterAll(async ({ request }) => {
  const [directory] = await getDirectory(request, { tenant, product });

  await deleteDirectory(request, directory.id);
});

test.describe('SCIM /api/scim/v2.0/:directoryId/Groups', () => {
  // POST /api/scim/v2.0/[directoryId]/Groups
  test('should be able to push a group with no members', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const response = await createGroup(request, directory, groups[0]);

    expect(response).toMatchObject({
      ...groups[0],
      id: expect.any(String),
      members: [],
    });
  });

  // GET /api/scim/v2.0/[directoryId]/Groups
  test('should be able to get a group by displayName', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const group = await getGroupByDisplayName(request, directory, groups[0].displayName);

    expect(group).toMatchObject({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      startIndex: 1,
      totalResults: 1,
      itemsPerPage: 1,
      Resources: [
        {
          ...groups[0],
          id: expect.any(String),
        },
      ],
    });
  });

  // GET /api/scim/v2.0/[directoryId]/Groups/[groupId]
  test('should be able to get a group by groupId', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const group = await getGroupByDisplayName(request, directory, groups[0].displayName);

    const response = await request.get(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      ...groups[0],
      id: expect.any(String),
    });
  });

  // PATCH /api/scim/v2.0/[directoryId]/Groups/[groupId]
  test('should be able to add a member to a group', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const user = await createUser(request, directory, users[0]);
    const group = await getGroupByDisplayName(request, directory, groups[0].displayName);

    const response = await request.patch(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'add',
            path: 'members',
            value: [
              {
                value: user.id,
                display: user.userName,
              },
            ],
          },
        ],
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      ...groups[0],
      id: expect.any(String),
      members: [],
    });

    // Fetch the group again and check that the member was added
    const updatedGroup = await getGroupById(request, directory, group.Resources[0].id);

    expect(updatedGroup).toMatchObject({
      ...groups[0],
      id: expect.any(String),
      members: [],
    });
  });

  // PATCH /api/scim/v2.0/[directoryId]/Groups/[groupId]
  test('should be able to remove a member from a group', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const user = await getUser(request, directory, users[0].userName);
    const group = await getGroupByDisplayName(request, directory, groups[0].displayName);

    const response = await request.patch(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'remove',
            path: `members[value eq "${user.Resources[0].id}"]`,
          },
        ],
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      ...groups[0],
      id: expect.any(String),
      members: [],
    });

    // Fetch the group again and check that the member was removed
    const updatedGroup = await getGroupById(request, directory, group.Resources[0].id);

    expect(updatedGroup).toMatchObject({
      ...groups[0],
      id: expect.any(String),
      members: [],
    });
  });

  // GET /api/scim/v2.0/[directoryId]/Groups
  test('should be able to get all groups', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });

    // Create second group
    await createGroup(request, directory, groups[1]);

    const response = await request.get(`${directory.scim.path}/Groups`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      startIndex: 1,
      totalResults: 2,
      itemsPerPage: 2,
      Resources: expect.arrayContaining([
        {
          ...groups[1],
          id: expect.any(String),
        },
        {
          ...groups[0],
          id: expect.any(String),
        },
      ]),
    });
  });

  // PATCH /api/scim/v2.0/[directoryId]/Groups/[groupId]
  test('should be able to update a group', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const group = await getGroupByDisplayName(request, directory, groups[0].displayName);

    const response = await request.patch(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'replace',
            value: {
              id: group.Resources[0].id,
              displayName: 'Developers Updated',
            },
          },
        ],
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);
    expect(await response.json()).toMatchObject({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id: group.Resources[0].id,
      displayName: 'Developers Updated',
      members: [],
    });

    // Fetch the group again and check the update was successful
    const updatedGroup = await getGroupById(request, directory, group.Resources[0].id);

    expect(updatedGroup).toMatchObject({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id: group.Resources[0].id,
      displayName: 'Developers Updated',
      members: [],
    });

    // Reverse the update so that it doesn't affect other tests
    await request.patch(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'replace',
            value: {
              id: group.Resources[0].id,
              displayName: 'Developers',
            },
          },
        ],
      },
    });
  });

  // DELETE /api/scim/v2.0/[directoryId]/Groups/[groupId]
  test('should be able to delete a group', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });
    const group = await getGroupByDisplayName(request, directory, groups[0].displayName);

    const response = await request.delete(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
    });

    expect(response.ok()).toBe(true);
    expect(response.status()).toBe(200);

    // Fetch the group again and check the update was successful
    const updatedGroup = await request.get(`${directory.scim.path}/Groups/${group.Resources[0].id}`, {
      headers: {
        Authorization: `Bearer ${directory.scim.secret}`,
      },
    });

    expect(updatedGroup.ok()).toBe(false);
    expect(updatedGroup.status()).toBe(404);
  });

  // POST /api/scim/v2.0/[directoryId]/Groups
  test('should be able to push a group with some members', async ({ request }) => {
    const [directory] = await getDirectory(request, { tenant, product });

    // Create some users
    const firstUser = await createUser(request, directory, users[1]);
    const secondUser = await createUser(request, directory, users[2]);

    const createdGroup = await createGroup(request, directory, {
      ...groups[0],
      members: [
        {
          value: firstUser.id,
          display: firstUser.userName,
        },
        {
          value: secondUser.id,
          display: secondUser.userName,
        },
      ],
    });

    expect(createdGroup).toMatchObject({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id: expect.any(String),
      displayName: groups[0].displayName,
      members: [],
    });
  });
});
