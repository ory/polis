// https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups#request
export const azureUser = (id: number) => ({
  schemas: [
    'urn:ietf:params:scim:schemas:core:2.0:User',
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
  ],
  externalId: `jackson-${id}`,
  userName: `jackson-${id}@boxyhq.onmicrosoft.com`,
  active: true,
  displayName: `Jackson-${id}`,
  emails: [{ primary: true, type: 'work', value: `jackson-${id}@example.com` }],
  meta: { resourceType: 'User' },
  name: { formatted: `samuel-${id} jackson-${id}`, familyName: `jackson-${id}`, givenName: `samuel-${id}` },
  title: 'Manager',
  roles: [],
});

export const updatedAzureUser = (id: number) => ({
  schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
  Operations: [
    {
      op: 'Replace',
      path: 'name.givenName',
      value: `samuel-${id}-updated`,
    },
    {
      op: 'Replace',
      path: 'name.familyName',
      value: `jackson-${id}-updated`,
    },
    {
      op: 'Replace',
      path: 'emails[type eq "work"].value',
      value: `jackson-${id}-updated@example.com`,
    },
  ],
});

export const azureGroup = {
  schemas: [
    'urn:ietf:params:scim:schemas:core:2.0:Group',
    'http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group',
  ],
  externalId: '8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159',
  displayName: 'Ory',
  meta: {
    resourceType: 'Group',
  },
};
