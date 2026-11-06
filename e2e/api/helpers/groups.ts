import { expect, type APIRequestContext } from '@playwright/test';
import type { Directory, Group } from '@boxyhq/saml-jackson';
import { scimOpUrl } from './utils';

export const createGroup = async (request: APIRequestContext, directory: Directory, group: any) => {
  const scimOpEndpoint = scimOpUrl(directory, 'Groups');
  const response = await request.post(scimOpEndpoint, {
    data: group,
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(201);

  return await response.json();
};

export const addGroupMember = async (
  request: APIRequestContext,
  directory: Directory,
  group: Group,
  member: string
) => {
  const scimOpEndpoint = scimOpUrl(directory, `Groups/${group.id}`);
  const response = await request.patch(scimOpEndpoint, {
    data: {
      Operations: [
        {
          action: 'addGroupMember',
          op: 'add',
          path: 'members',
          value: [
            {
              value: member,
            },
          ],
        },
      ],
    },
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

export const getGroupByDisplayName = async (
  request: APIRequestContext,
  directory: Directory,
  displayName: string
) => {
  const response = await request.get(`${directory.scim.path}/Groups`, {
    params: {
      filter: `displayName eq "${displayName}"`,
    },
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

export const getGroupById = async (request: APIRequestContext, directory: Directory, groupId: string) => {
  const response = await request.get(`${directory.scim.path}/Groups/${groupId}`, {
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

export const getGroupsByDirectoryId = async (request: APIRequestContext, directory: Directory) => {
  const response = await request.get(`${directory.scim.path}/Groups`, {
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  const data = await response.json();
  return data.Resources;
};

export const deleteGroup = async (request: APIRequestContext, directory: Directory, groupId: string) => {
  const scimOpEndpoint = scimOpUrl(directory, `Groups/${groupId}`);

  const response = await request.delete(scimOpEndpoint, {
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });

  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);

  return await response.json();
};

export const updateGroupName = async (
  request: APIRequestContext,
  directory: Directory,
  groupId: string,
  newName: string
) => {
  const scimOpEndpoint = scimOpUrl(directory, `Groups/${groupId}`);
  const response = await request.patch(scimOpEndpoint, {
    data: {
      Operations: [
        {
          op: 'replace',
          path: 'displayName',
          value: newName,
        },
      ],
    },
    headers: {
      Authorization: `Bearer ${directory.scim.secret}`,
    },
  });
  expect(response.ok()).toBe(true);
  expect(response.status()).toBe(200);
};
