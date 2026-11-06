import tap from 'tap';
import nock from 'nock';
import type { DirectorySyncEvent, JacksonOption } from '@boxyhq/saml-jackson';

import { jacksonOptions } from '../utils';
import { IDirectorySyncController, DirectoryType } from '../../src/typings';

let directorySyncController: IDirectorySyncController;

const directoryPayload = {
  tenant: 'boxyhq',
  product: 'saml-jackson-google',
  name: 'Google Directory',
  type: 'google' as DirectoryType,
  google_access_token: 'access_token',
  google_refresh_token: 'refresh_token',
};

type User = {
  id: string;
  primaryEmail: string;
  name: {
    givenName: string;
    familyName: string;
  };
  suspended: boolean;
  password: string;
  hashFunction: string;
  changePasswordAtNextLogin: boolean;
  ipWhitelisted: boolean;
  etag: string;
};

const fakeGoogleDirectory = {
  users: [] as User[],
  groups: [
    {
      id: 'engineering',
      email: 'engineering@example.com',
      name: 'Engineering Team',
      description: 'A group for the engineering department',
      adminCreated: true,
      directMembersCount: '10',
      kind: 'admin#directory#group',
      etag: 'abcd1234',
      aliases: ['eng-team@example.com', 'engineering@example.com'],
      nonEditableAliases: ['group123@example.com'],
    },
    {
      id: 'sales',
      email: 'sales@example.com',
      name: 'Sales Team',
      description: 'A group for the sales department',
      adminCreated: true,
      directMembersCount: '5',
      kind: 'admin#directory#group',
      etag: 'efgh5678',
      aliases: ['sales@example.com'],
      nonEditableAliases: ['sales-group456@example.com'],
    },
  ],
  members: {
    engineering: [
      {
        kind: 'directory#member',
        id: 'elizasmith1',
        email: 'eliza1@example.com',
        role: 'MANAGER',
        type: 'USER',
      },
      {
        kind: 'directory#member',
        id: 'elizasmith2',
        email: 'elizasmith2@example.com',
        role: 'MANAGER',
        type: 'USER',
      },
    ],
    sales: [
      {
        kind: 'directory#member',
        id: 'elizasmith1',
        email: 'eliza1@example.com',
        role: 'MANAGER',
        type: 'USER',
      },
    ],
    marketing: [
      {
        kind: 'directory#member',
        id: 'jackson',
        email: 'jackson@example.com',
        role: 'MANAGER',
        type: 'USER',
      },
    ],
  },
};

for (let i = 1; i <= 5000; i++) {
  fakeGoogleDirectory.users.push({
    id: `elizasmith${i}`,
    primaryEmail: `eliza${i}@example.com`,
    name: {
      givenName: `Eliza${i}`,
      familyName: 'Smith',
    },
    suspended: false,
    password: 'password',
    hashFunction: 'SHA-1',
    changePasswordAtNextLogin: false,
    ipWhitelisted: false,
    etag: 'abcd1234',
  });
}

const pageSize = 200;
const numOfPages = fakeGoogleDirectory.users.length / pageSize;
// Mock /admin/directory/v1/users
const mockUsersAPI = async (users: any[]) => {
  for (let i = 0; i < users.length / pageSize; i++) {
    const query: any = {
      maxResults: 200,
      customer: 'my_customer',
    };
    if (i !== 0) {
      query.pageToken = `${i}`;
    }
    const _users = users.slice(i * pageSize, i * pageSize + pageSize);
    nock('https://admin.googleapis.com')
      .get('/admin/directory/v1/users')
      .query(query)
      .reply(200, { users: _users, nextPageToken: i === numOfPages - 1 ? undefined : `${i + 1}` });
  }
};

// Mock /admin/directory/v1/groups
const mockGroupsAPI = (groups: any[]) => {
  nock('https://admin.googleapis.com')
    .get('/admin/directory/v1/groups')
    .query({
      maxResults: 200,
      customer: 'my_customer',
    })
    // Gets invoked 2 times - 1 for syncGroups, 2nd time inside syncGroupMembers
    .times(2)
    .reply(200, { groups });
};

// Mock /admin/directory/v1/groups/{groupKey}/members
const mockGroupMembersAPI = (groupKey: string, members: any[]) => {
  nock('https://admin.googleapis.com')
    .get(`/admin/directory/v1/groups/${groupKey}/members`)
    .query({
      maxResults: 200,
    })
    .reply(200, { members });
};

let events: DirectorySyncEvent[] = [];

tap.before(async () => {
  const options: JacksonOption = {
    ...jacksonOptions,
    dsync: {
      callback: async (event: DirectorySyncEvent) => {
        events.push(event);
      },
    },
  };

  directorySyncController = (await (await import('../../src/index')).default(options))
    .directorySyncController;

  await directorySyncController.directories.create(directoryPayload);
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('Sync 1', async (t) => {
  events = [];

  // Mock necessary API calls
  mockUsersAPI(fakeGoogleDirectory.users);
  mockGroupsAPI(fakeGoogleDirectory.groups);
  mockGroupMembersAPI('engineering', fakeGoogleDirectory.members.engineering);
  mockGroupMembersAPI('sales', fakeGoogleDirectory.members.sales);

  await directorySyncController.sync();

  nock.cleanAll();
  // 5k users, 2 groups, 3 group members
  t.strictSame(events.length, 5005);

  t.strictSame(events[0].event, 'user.created');
  t.strictSame(events[0].data.id, fakeGoogleDirectory.users[0].id);
  t.strictSame(events[0].data.raw, fakeGoogleDirectory.users[0]);

  t.strictSame(events[4999].event, 'user.created');
  t.strictSame(events[4999].data.id, fakeGoogleDirectory.users[4999].id);
  t.strictSame(events[4999].data.raw, fakeGoogleDirectory.users[4999]);

  t.strictSame(events[5000].event, 'group.created');
  t.strictSame(events[5000].data.id, fakeGoogleDirectory.groups[0].id);
  t.strictSame(events[5000].data.raw, fakeGoogleDirectory.groups[0]);

  t.strictSame(events[5001].event, 'group.created');
  t.strictSame(events[5001].data.id, fakeGoogleDirectory.groups[1].id);
  t.strictSame(events[5001].data.raw, fakeGoogleDirectory.groups[1]);

  t.strictSame(events[5002].event, 'group.user_added');
  t.strictSame(events[5002].data.id, fakeGoogleDirectory.users[0].id);
  t.strictSame(events[5002].data.raw, fakeGoogleDirectory.users[0]);

  // Check that the user was added to the group
  if ('group' in events[5002].data) {
    t.strictSame(events[5002].data.group.id, fakeGoogleDirectory.groups[0].id);
  }

  t.strictSame(events[5003].event, 'group.user_added');
  t.strictSame(events[5003].data.id, fakeGoogleDirectory.users[1].id);
  t.strictSame(events[5003].data.raw, fakeGoogleDirectory.users[1]);

  // Check that the user was added to the group
  if ('group' in events[5003].data) {
    t.strictSame(events[5003].data.group.id, fakeGoogleDirectory.groups[0].id);
  }

  t.strictSame(events[5004].event, 'group.user_added');
  t.strictSame(events[5004].data.id, fakeGoogleDirectory.users[0].id);
  t.strictSame(events[5004].data.raw, fakeGoogleDirectory.users[0]);

  // Check that the user was added to the group
  if ('group' in events[5004].data) {
    t.strictSame(events[5004].data.group.id, fakeGoogleDirectory.groups[1].id);
  }

  t.end();
});

tap.test('Sync 2', async (t) => {
  events = [];

  // Update user
  fakeGoogleDirectory.users[0].name.givenName = 'Eliza Updated';

  // Update group
  fakeGoogleDirectory.groups[0].name = 'Engineering Updated';

  mockUsersAPI(fakeGoogleDirectory.users);
  mockGroupsAPI(fakeGoogleDirectory.groups);
  mockGroupMembersAPI('engineering', fakeGoogleDirectory.members.engineering);
  mockGroupMembersAPI('sales', fakeGoogleDirectory.members.sales);

  await directorySyncController.sync();

  nock.cleanAll();

  t.strictSame(events.length, 2);

  t.strictSame(events[0].event, 'user.updated');
  t.strictSame(events[0].data.id, fakeGoogleDirectory.users[0].id);
  t.strictSame(events[0].data.raw, fakeGoogleDirectory.users[0]);

  t.strictSame(events[1].event, 'group.updated');
  t.strictSame(events[1].data.id, fakeGoogleDirectory.groups[0].id);
  t.strictSame(events[1].data.raw, fakeGoogleDirectory.groups[0]);

  t.end();
});

tap.test('Sync 3', async (t) => {
  events = [];

  // Delete the last user
  const deleteUser = fakeGoogleDirectory.users.pop();

  // Delete the last group
  const deleteGroup = fakeGoogleDirectory.groups.pop();

  // Clear the members
  fakeGoogleDirectory.members.sales = [];

  mockUsersAPI(fakeGoogleDirectory.users);
  mockGroupsAPI(fakeGoogleDirectory.groups);
  mockGroupMembersAPI('engineering', fakeGoogleDirectory.members.engineering);

  await directorySyncController.sync();

  nock.cleanAll();

  t.strictSame(events.length, 2);

  t.strictSame(events[0].event, 'user.deleted');
  t.strictSame(events[0].data.id, deleteUser?.id);
  t.strictSame(events[0].data.raw, deleteUser);

  t.strictSame(events[1].event, 'group.deleted');
  t.strictSame(events[1].data.id, deleteGroup?.id);
  t.strictSame(events[1].data.raw, deleteGroup);

  t.end();
});

tap.test('Sync 4', async (t) => {
  events = [];

  // Add new user
  const newUser = {
    ...fakeGoogleDirectory.users[0],
    id: 'jackson',
    primaryEmail: 'jackson@example.com',
    name: {
      givenName: 'Jackson',
      familyName: 'Smith',
    },
  };

  // Add new group
  const newGroup = {
    ...fakeGoogleDirectory.groups[0],
    id: 'marketing',
    email: 'marketing@example.com',
    name: 'Marketing Team',
    description: 'A group for the marketing department',
  };

  fakeGoogleDirectory.users.push(newUser);
  fakeGoogleDirectory.groups.push(newGroup);

  mockUsersAPI(fakeGoogleDirectory.users);
  mockGroupsAPI(fakeGoogleDirectory.groups);
  mockGroupMembersAPI('engineering', fakeGoogleDirectory.members.engineering);
  mockGroupMembersAPI('marketing', fakeGoogleDirectory.members.marketing);

  await directorySyncController.sync();

  nock.cleanAll();

  t.strictSame(events.length, 3);

  t.strictSame(events[0].event, 'user.created');
  t.strictSame(events[0].data.id, newUser.id);
  t.strictSame(events[0].data.raw, newUser);

  t.strictSame(events[1].event, 'group.created');
  t.strictSame(events[1].data.id, newGroup.id);
  t.strictSame(events[1].data.raw, newGroup);

  t.strictSame(events[2].event, 'group.user_added');
  t.strictSame(events[2].data.id, newUser.id);
  t.strictSame(events[2].data.raw, newUser);

  // Check that the user was added to the group
  if ('group' in events[2].data) {
    t.strictSame(events[2].data.group.id, newGroup.id);
  }

  t.end();
});

tap.test('Sync 5', async (t) => {
  events = [];

  // Remove elizasmith1 from the engineering group
  fakeGoogleDirectory.members.engineering.shift();

  // Add elizasmith1 to the marketing group
  fakeGoogleDirectory.members.marketing.push({
    kind: 'directory#member',
    id: 'elizasmith1',
    email: 'eliza1@example.com',
    role: 'MANAGER',
    type: 'USER',
  });

  mockUsersAPI(fakeGoogleDirectory.users);
  mockGroupsAPI(fakeGoogleDirectory.groups);
  mockGroupMembersAPI('engineering', fakeGoogleDirectory.members.engineering);
  mockGroupMembersAPI('marketing', fakeGoogleDirectory.members.marketing);

  await directorySyncController.sync();

  nock.cleanAll();

  t.strictSame(events.length, 2);

  t.strictSame(events[0].event, 'group.user_removed');
  t.strictSame(events[0].data.id, fakeGoogleDirectory.users[0].id);
  t.strictSame(events[0].data.raw, fakeGoogleDirectory.users[0]);

  // Check that the user was removed from the group
  if ('group' in events[0].data) {
    t.strictSame(events[0].data.group.id, fakeGoogleDirectory.groups[0].id);
  }

  t.strictSame(events[1].event, 'group.user_added');
  t.strictSame(events[1].data.id, fakeGoogleDirectory.users[0].id);
  t.strictSame(events[1].data.raw, fakeGoogleDirectory.users[0]);

  // Check that the user was added to the group
  if ('group' in events[1].data) {
    t.strictSame(events[1].data.group.id, fakeGoogleDirectory.groups[1].id);
  }

  t.end();
});
