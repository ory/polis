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

  // Entra ID-style PATCH with SCIM filter paths for phone numbers and addresses
  entraPhoneAndAddress: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      body: {
        Operations: [
          {
            op: 'replace',
            path: 'phoneNumbers[type eq "work"].value',
            value: '555-0100',
          },
          {
            op: 'replace',
            path: 'phoneNumbers[type eq "mobile"].value',
            value: '555-0101',
          },
          {
            op: 'replace',
            path: 'addresses[type eq "work"].streetAddress',
            value: '100 Enterprise Blvd',
          },
          {
            op: 'replace',
            path: 'addresses[type eq "work"].locality',
            value: 'San Francisco',
          },
          {
            op: 'replace',
            path: 'addresses[type eq "work"].postalCode',
            value: '94105',
          },
          {
            op: 'replace',
            path: 'addresses[type eq "work"].country',
            value: 'US',
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

  // Arbitrary attribute names with SCIM filter paths (e.g. ims, photos)
  arbitraryFilterPaths: (directory: Directory, userId: string): DirectorySyncRequest => {
    return {
      method: 'PATCH',
      body: {
        Operations: [
          {
            op: 'replace',
            path: 'ims[type eq "xmpp"].value',
            value: 'test@test.org',
          },
          {
            op: 'replace',
            path: 'photos[type eq "thumbnail"].value',
            value: 'https://example.com/photo.jpg',
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
