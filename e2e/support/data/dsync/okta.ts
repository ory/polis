// https://developer.okta.com/docs/reference/scim/scim-20/#create-the-user
export const oktaUser = (id: number) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName: `jackson-${id}@boxyhq.okta.local`,
  name: { familyName: `jackson-${id}`, givenName: `samuel-${id}` },
  emails: [{ primary: true, type: 'work', value: `jackson-${id}@okta.local` }],
  displayName: `Jackson-${id}`,
  locale: 'en-US',
  externalId: `jackson-${id}`,
  groups: [],
  password: `jackson-password-${id}`,
  active: true,
});

export const updatedOktaUser = (id: number) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName: `jackson-${id}@boxyhq.okta.local`,
  name: { familyName: `jackson-${id}-updated`, givenName: `samuel-${id}-updated` },
  emails: [{ primary: true, type: 'work', value: `jackson-${id}-updated@okta.local` }],
  displayName: `Jackson-${id}`,
  locale: 'en-US',
  externalId: `jackson-${id}`,
  groups: [],
  password: `jackson-password-${id}`,
  active: true,
});

export const oktaGroup = {
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
