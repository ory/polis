const rolesAttribute = 'roles';
const rolesSchema = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role';

const groupsAttribute = 'groups';
const groupsSchema = 'http://schemas.xmlsoap.org/claims/Group';

const arrayMapping = [
  {
    attribute: rolesAttribute,
    schema: rolesSchema,
  },
  {
    attribute: groupsAttribute,
    schema: groupsSchema,
  },
];

const mapping = [
  {
    attribute: 'id',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
  },
  {
    attribute: 'email',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  },
  {
    attribute: 'firstName',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
  },
  {
    attribute: 'lastName',
    schema: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
  },
  ...arrayMapping,
];

type attributes = (typeof mapping)[number]['attribute'];
type schemas = (typeof mapping)[number]['schema'];

const map = (claims: Record<attributes | schemas, unknown>) => {
  arrayMapping.forEach((m) => {
    if (claims[m.attribute]) {
      claims[m.attribute] = [].concat(claims[m.attribute] as any);
    } else if (claims[m.schema]) {
      claims[m.schema] = [].concat(claims[m.schema] as any);
    }
  });

  const profile = {
    raw: claims,
  };

  mapping.forEach((m) => {
    if (claims[m.attribute]) {
      profile[m.attribute] = claims[m.attribute];
    } else if (claims[m.schema]) {
      profile[m.attribute] = claims[m.schema];
    }
  });

  return profile;
};

export default { map };
