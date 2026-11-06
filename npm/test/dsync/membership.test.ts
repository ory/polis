import { IDirectorySyncController, Directory, Group, DirectorySyncEvent } from '../../src/typings';
import tap from 'tap';
import groups from './data/groups';
import users from './data/users';
import { default as usersRequest } from './data/user-requests';
import { createGroupMembershipRequest } from './data/group-requests';
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
});
