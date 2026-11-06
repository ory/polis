import type { DirectorySyncRequest, Directory, Group } from '../../../src/typings';

const requests = {
  // Create a group
  // POST /api/scim/v2.0/{directoryId: directory.id}/Groups
  create: (directory: Directory, group: any): DirectorySyncRequest => {
    return {
      method: 'POST',
      body: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        displayName: group.displayName,
        members: [],
      },
      directoryId: directory.id,
      resourceType: 'groups',
      resourceId: undefined,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // Get a group by id
  // GET /api/scim/v2.0/{directoryId: directory.id}/Groups/{groupId}
  getById: (directory: Directory, groupId: string): DirectorySyncRequest => {
    return {
      method: 'GET',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'groups',
      resourceId: groupId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // Filter by displayName
  // GET /api/scim/v2.0/{directoryId: directory.id}/Groups?filter=displayName eq "{displayName}"
  filterByDisplayName: (directory: Directory, displayName: string): DirectorySyncRequest => {
    return {
      method: 'GET',
      directoryId: directory.id,
      body: undefined,
      resourceType: 'groups',
      resourceId: undefined,
      apiSecret: directory.scim.secret,
      query: {
        filter: `displayName eq "${displayName}"`,
      },
    };
  },

  // Update a group by id
  // PUT /api/scim/v2.0/{directoryId: directory.id}/Groups/{groupId}
  updateById: (directory: Directory, groupId: string, group: any): DirectorySyncRequest => {
    return {
      method: 'PUT',
      body: group,
      directoryId: directory.id,
      resourceType: 'groups',
      resourceId: groupId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // Delete a group by id
  // DELETE /api/scim/v2.0/{directoryId: directory.id}/Groups/{groupId}
  deleteById: (directory: Directory, groupId: string): DirectorySyncRequest => {
    return {
      method: 'DELETE',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'groups',
      resourceId: groupId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // Get all groups
  // GET /api/scim/v2.0/{directoryId: directory.id}/Groups
  getAll: (directory: Directory): DirectorySyncRequest => {
    return {
      method: 'GET',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'groups',
      resourceId: undefined,
      apiSecret: directory.scim.secret,
      query: {
        count: 1,
        startIndex: 1,
      },
    };
  },

  updateName: (directory: Directory, groupId: string, group: any): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      directoryId: directory.id,
      body: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'replace',
            value: {
              id: groupId,
              displayName: group.displayName,
            },
          },
        ],
      },
      resourceType: 'groups',
      resourceId: groupId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  addMembers: (directory: Directory, groupId: string, members: any): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      directoryId: directory.id,
      body: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'add',
            path: 'members',
            value: members,
          },
        ],
      },
      resourceType: 'groups',
      resourceId: groupId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  removeMembers: (
    directory: Directory,
    groupId: string,
    members: any,
    path: string
  ): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      directoryId: directory.id,
      body: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          {
            op: 'remove',
            value: members,
            path,
          },
        ],
      },
      resourceType: 'groups',
      resourceId: groupId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },
};

export const createGroupMembershipRequest = (
  directory: Directory,
  group: Group,
  operations: any
): DirectorySyncRequest => {
  return {
    body: {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: operations,
    },
    method: 'PATCH',
    directoryId: directory.id,
    apiSecret: directory.scim.secret,
    resourceId: group.id,
    resourceType: 'groups',
    query: {},
  };
};

export default requests;
