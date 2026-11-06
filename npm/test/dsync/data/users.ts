const users = [
  {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: 'jackson@boxyhq.com',
    name: {
      givenName: 'Jackson',
      familyName: 'M',
      formatted: 'Jackson M',
    },
    emails: [
      {
        primary: true,
        value: 'jackson@boxyhq.com',
        type: 'work',
      },
    ],
    meta: {
      resourceType: 'User',
    },
    displayName: 'Jackson M',
    locale: 'en-US',
    externalId: '00u5b1hpjh9tGaknX5d7',
    groups: [],
    active: true,
    title: 'Manager',
  },
  {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: 'kiran@boxyhq.com',
    name: {
      givenName: 'Kiran',
      familyName: 'K',
    },
    emails: [
      {
        primary: true,
        value: 'kiran@boxyhq.com',
        type: 'work',
      },
    ],
    displayName: 'Kiran K',
    locale: 'en-US',
    externalId: '00u1b1hpjh91GaknX5d7',
    groups: [],
    active: true,
  },
  {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: 'david@example.com',
    name: {
      givenName: 'David',
      familyName: 'Phillips',
    },
    emails: [
      {
        primary: true,
        value: 'david@example.com',
        type: 'work',
      },
    ],
    displayName: 'David Phillips',
    locale: 'en-US',
    externalId: '00u1b1hpjh91GaknX547',
    groups: [],
    active: true,
  },
];

export default users;
