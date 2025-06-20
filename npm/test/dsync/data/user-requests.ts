import type { Directory, DirectorySyncRequest } from '../../../src/typings';

const requests = {
  create: (directory: Directory, user: any): DirectorySyncRequest => {
    return {
      method: 'POST',
      body: user,
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: undefined,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // GET /Users?filter=userName eq "userName"
  filterByUsername: (directory: Directory, userName: string): DirectorySyncRequest => {
    return {
      method: 'GET',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: undefined,
      apiSecret: directory.scim.secret,
      query: {
        filter: `userName eq "${userName}"`,
        count: 1,
        startIndex: 1,
      },
    };
  },

  // GET /Users/{userId}
  getById: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'GET',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: userId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // PUT /Users/{userId}
  updateById: (directory: Directory, userId: string, user: any): DirectorySyncRequest => {
    return {
      method: 'PUT',
      body: user,
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: userId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // PATCH /Users/{userId}
  updateOperationById: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      body: {
        Operations: [
          {
            op: 'replace',
            value: {
              active: false,
            },
          },
        ],
      },
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: userId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // GET /Users/
  getAll: (directory: Directory): DirectorySyncRequest => {
    return {
      method: 'GET',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: undefined,
      apiSecret: directory.scim.secret,
      query: {
        count: 1,
        startIndex: 1,
      },
    };
  },

  // DELETE /Users/{userId}
  deleteById: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'DELETE',
      body: undefined,
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: userId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // Multi-valued properties
  multiValuedProperties: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      body: {
        Operations: [
          {
            op: 'replace',
            path: 'name.givenName',
            value: 'David',
          },
          {
            op: 'replace',
            path: 'name.familyName',
            value: 'Jones',
          },
          {
            op: 'replace',
            value: { active: false },
          },
        ],
      },
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: userId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },

  // Custom attributes
  customAttributes: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      body: {
        Operations: [
          {
            op: 'replace',
            path: 'companyName',
            value: 'Ory',
          },
          {
            op: 'add',
            path: 'address.streetAddress',
            value: '123 Main St',
          },
        ],
      },
      directoryId: directory.id,
      resourceType: 'users',
      resourceId: userId,
      apiSecret: directory.scim.secret,
      query: {},
    };
  },
};

export default requests;
