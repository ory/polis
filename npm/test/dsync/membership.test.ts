import { IDirectorySyncController, Directory, Group, DirectorySyncEvent } from '../../src/typings';
import tap from 'tap';
import groups from './data/groups';
import users from './data/users';
import { default as usersRequest } from './data/user-requests';
import { default as groupsRequest, createGroupMembershipRequest } from './data/group-requests';
import { getFakeDirectory } from './data/directories';
import { jacksonOptions } from '../utils';

const fakeDirectory = getFakeDirectory();
let directorySync: IDirectorySyncController;
let directory: Directory;
let group: Group;

tap.before(async () => {
  const jackson = await (await import('../../src/index')).default(jacksonOptions);

  directorySync = jackson.directorySyncController;

  const directoryResponse = await directorySync.directories.create(fakeDirectory);

  if (!directoryResponse.data) {
    tap.fail("Couldn't create a directory");
    return;
  }

  directory = directoryResponse.data;

  const groupResponse = await directorySync.groups
    .setTenantAndProduct(directory.tenant, directory.product)
    .create({
      directoryId: directory.id,
      name: groups[0].displayName,
      raw: groups[0],
    });

  if (!groupResponse.data) {
    tap.fail("Couldn't create a group");
    return;
  }

  group = groupResponse.data;
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('Directory groups membership /', async (t) => {
  t.teardown(async () => {
    await directorySync.directories.delete(directory.id);
    await directorySync.groups.delete(group.id);
  });

  t.test('Directory groups membership /', async (t) => {
    const { data: user1 } = await directorySync.requests.handle(usersRequest.create(directory, users[0]));
    const { data: user2 } = await directorySync.requests.handle(usersRequest.create(directory, users[1]));

    t.match(await directorySync.groups.isUserInGroup(group.id, user1.id), false);

    let request = createGroupMembershipRequest(directory, group, [
      {
        op: 'add',
        path: 'members',
        value: [
          {
            value: user1.id,
          },
        ],
      },
    ]);

    // Add a member to an existing group
    await directorySync.requests.handle(request, async (event: DirectorySyncEvent) => {
      t.match(event.event, 'group.user_added');
      t.match(event.data.id, user1.id);

      if ('group' in event.data) {
        t.match(event.data.group.id, group.id);
        t.match(event.data.group.name, 'Developers');
      }
    });

    t.match(await directorySync.groups.isUserInGroup(group.id, user1.id), true);

    request = createGroupMembershipRequest(directory, group, [
      {
        op: 'remove',
        path: `members[value eq "${user1.id}"]`,
      },
    ]);

    // Remove a member from an existing group
    await directorySync.requests.handle(request, async (event: DirectorySyncEvent) => {
      t.match(event.event, 'group.user_removed');
      t.match(event.data.id, user1.id);

      if ('group' in event.data) {
        t.match(event.data.group.id, group.id);
        t.match(event.data.group.name, 'Developers');
      }
    });

    t.match(await directorySync.groups.isUserInGroup(group.id, user1.id), false);

    request = createGroupMembershipRequest(directory, group, [
      {
        op: 'add',
        path: 'members',
        value: [
          {
            value: user1.id,
          },
          {
            value: user2.id,
          },
        ],
      },
    ]);

    // Handle multiple operations in a single request
    await directorySync.requests.handle(request, async (event: DirectorySyncEvent) => {
      t.match(event.event, 'group.user_added');
      t.match([user1.id, user2.id].includes(event.data.id), true);

      if ('group' in event.data) {
        t.match(event.data.group.id, group.id);
        t.match(event.data.group.name, 'Developers');
      }
    });

    t.match(await directorySync.groups.isUserInGroup(group.id, user1.id), true);
    t.match(await directorySync.groups.isUserInGroup(group.id, user2.id), true);

    // Without the includeMembers flag, members stay empty (default behavior).
    const { data: groupWithoutMembers } = await directorySync.requests.handle(
      groupsRequest.getById(directory, group.id)
    );

    t.equal(groupWithoutMembers.members.length, 0);

    // With includeMembers=true, the response reflects the current members.
    const { data: groupById } = await directorySync.requests.handle(
      groupsRequest.getById(directory, group.id, true)
    );

    t.equal(groupById.members.length, 2);
    t.same(
      groupById.members.map((member: { value: string }) => member.value).sort(),
      [user1.id, user2.id].sort()
    );

    // The group list endpoint honors the flag too.
    const { data: allGroups } = await directorySync.requests.handle(groupsRequest.getAll(directory, true));
    const groupResource = allGroups.Resources.find((resource: any) => resource.id === group.id);

    t.ok(groupResource);
    t.equal(groupResource.members.length, 2);
    t.same(
      groupResource.members.map((member: { value: string }) => member.value).sort(),
      [user1.id, user2.id].sort()
    );

    // The group list endpoint omits members by default.
    const { data: allGroupsNoMembers } = await directorySync.requests.handle(groupsRequest.getAll(directory));
    const groupResourceNoMembers = allGroupsNoMembers.Resources.find(
      (resource: any) => resource.id === group.id
    );

    t.ok(groupResourceNoMembers);
    t.equal(groupResourceNoMembers.members.length, 0);

    request = createGroupMembershipRequest(directory, group, [
      {
        op: 'remove',
        path: 'members',
        value: [
          {
            value: user1.id,
          },
          {
            value: user2.id,
          },
        ],
      },
    ]);

    // Remove all members from an existing group
    await directorySync.requests.handle(request, async (event: DirectorySyncEvent) => {
      t.match(event.event, 'group.user_removed');
      t.match([user1.id, user2.id].includes(event.data.id), true);

      if ('group' in event.data) {
        t.match(event.data.group.id, group.id);
        t.match(event.data.group.name, 'Developers');
      }
    });

    t.match(await directorySync.groups.isUserInGroup(group.id, user1.id), false);
    t.match(await directorySync.groups.isUserInGroup(group.id, user2.id), false);
  });

  t.test('Should return an error when a group exceeds the inline member limit', async (t) => {
    const { data: largeGroup } = await directorySync.groups
      .setTenantAndProduct(directory.tenant, directory.product)
      .create({
        directoryId: directory.id,
        name: 'Large group',
        raw: { displayName: 'Large group', members: [] },
      });

    if (!largeGroup) {
      t.fail("Couldn't create the large group");
      return;
    }

    t.teardown(async () => {
      await directorySync.groups.delete(largeGroup.id);
    });

    // Add more members than the inline limit (500).
    for (let i = 0; i <= 500; i++) {
      await directorySync.groups.addUserToGroup(largeGroup.id, `user-${i}`);
    }

    // Without the flag, the request still succeeds with an empty members list.
    const { status: defaultStatus, data: defaultData } = await directorySync.requests.handle(
      groupsRequest.getById(directory, largeGroup.id)
    );

    t.equal(defaultStatus, 200);
    t.equal(defaultData.members.length, 0);

    // With the flag, the oversized group is rejected instead of loaded inline.
    const { status, data } = await directorySync.requests.handle(
      groupsRequest.getById(directory, largeGroup.id, true)
    );

    t.equal(status, 400);
    t.match(data.detail, /more than 500 members/);

    t.end();
  });
});

tap.test('Configurable inline group member limit', async (t) => {
  // Spin up a controller with a low limit to verify the threshold is honored.
  const limit = 2;
  const jackson = await (
    await import('../../src/index')
  ).default({
    ...jacksonOptions,
    dsync: { ...jacksonOptions.dsync, maxInlineGroupMembers: limit },
  });

  const customSync = jackson.directorySyncController;

  const { data: customDirectory } = await customSync.directories.create(getFakeDirectory());

  if (!customDirectory) {
    t.fail("Couldn't create a directory");
    return;
  }

  const { data: customGroup } = await customSync.groups
    .setTenantAndProduct(customDirectory.tenant, customDirectory.product)
    .create({
      directoryId: customDirectory.id,
      name: 'Configurable group',
      raw: { displayName: 'Configurable group', members: [] },
    });

  if (!customGroup) {
    t.fail("Couldn't create a group");
    return;
  }

  t.teardown(async () => {
    await customSync.directories.delete(customDirectory.id);
    await customSync.groups.delete(customGroup.id);
  });

  // At the limit, the members are returned.
  for (let i = 0; i < limit; i++) {
    await customSync.groups.addUserToGroup(customGroup.id, `user-${i}`);
  }

  const atLimit = await customSync.requests.handle(
    groupsRequest.getById(customDirectory, customGroup.id, true)
  );

  t.equal(atLimit.status, 200);
  t.equal(atLimit.data.members.length, limit);

  // One over the configured limit is rejected.
  await customSync.groups.addUserToGroup(customGroup.id, `user-${limit}`);

  const overLimit = await customSync.requests.handle(
    groupsRequest.getById(customDirectory, customGroup.id, true)
  );

  t.equal(overLimit.status, 400);
  t.match(overLimit.data.detail, new RegExp(`more than ${limit} members`));

  t.end();
});
