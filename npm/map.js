const map = {
  'test/sso/saml_idp_api.test.ts': ['src/controller/api.ts', 'src/controller/connection/saml.ts'],
  'test/sso/oidc_idp_api.test.ts': ['src/controller/api.ts', 'src/controller/connection/oidc.ts'],
  'test/sso/saml_idp_oauth.test.ts': [
    'src/controller/oauth.ts',
    'src/controller/oauth/*',
    'src/controller/utils.ts',
  ],
  'test/sso/oidc_idp_oauth.test.ts': [
    'src/controller/oauth.ts',
    'src/controller/oauth/*',
    'src/controller/utils.ts',
  ],
  'test/sso/logout.test.ts': ['src/controller/logout.ts', 'src/controller/utils.ts'],
  'test/db/db.test.ts': ['src/db/*'],

  'test/dsync/directories.test.ts': ['src/directory-sync/DirectoryConfig.ts'],
  'test/dsync/users.test.ts': [
    'src/directory-sync/DirectoryUsers.ts',
    'src/directory-sync/Users.ts',
    'src/directory-sync/request.ts',
  ],
  'test/dsync/groups.test.ts': [
    'src/directory-sync/DirectoryGroups.ts',
    'src/directory-sync/Groups.ts',
    'src/directory-sync/request.ts',
  ],
  'test/dsync/events.test.ts': ['src/directory-sync/events.ts'],
  'test/identity-federation/app.test.ts': ['src/ee/identity-federation/app.ts'],
  'test/identity-federation/sso.test.ts': ['src/ee/identity-federation/sso.ts'],
  'test/event/index.test.ts': ['src/event/*'],
  'test/dsync/google_oauth.test.ts': [
    'src/directory-sync/non-scim/google/oauth.ts',
    'src/directory-sync/non-scim/google/index.ts',
    'src/directory-sync/non-scim/utils.ts',
  ],
  'test/dsync/google_api.test.ts': [
    'src/directory-sync/non-scim/google/api.ts',
    'src/directory-sync/non-scim/google/index.ts',
    'src/directory-sync/non-scim/syncUsers.ts',
    'src/directory-sync/non-scim/syncGroups.ts',
    'src/directory-sync/non-scim/syncGroupsMembers.ts',
    'src/directory-sync/non-scim/utils.ts',
    'src/directory-sync/non-scim/index.ts',
  ],
};

module.exports = (testFile) => {
  return map[testFile] || [];
};
