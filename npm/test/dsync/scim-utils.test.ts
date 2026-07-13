import tap from 'tap';
import { parseGroupOperation, parseUserPatchRequest } from '../../src/directory-sync/scim/utils';
import type { GroupPatchOperation, UserPatchOperation } from '../../src/directory-sync/types';

// Microsoft Entra sends PascalCase SCIM PATCH ops ("Add"/"Remove"/"Replace")
// unless the tenant enables the aadOptscim062020 flag. These bodies arrive off
// the wire, so op can hold values outside the declared lowercase union.
const groupOp = (op: string, path: string, value: unknown) =>
  parseGroupOperation({ op, path, value } as unknown as GroupPatchOperation);

tap.test('parseGroupOperation parses SCIM PATCH op case-insensitively', async (t) => {
  const members = [{ value: 'u1091' }];

  t.equal(groupOp('Add', 'members', members).action, 'addGroupMember');
  t.equal(groupOp('Remove', 'members', members).action, 'removeGroupMember');
  t.equal(groupOp('Replace', 'displayName', 'Eng').action, 'updateGroupName');

  // Lowercase ops (Entra with aadOptscim062020, and other IdPs) still parse.
  t.equal(groupOp('add', 'members', members).action, 'addGroupMember');
  t.equal(groupOp('remove', 'members', members).action, 'removeGroupMember');
  t.equal(groupOp('replace', 'displayName', 'Eng').action, 'updateGroupName');

  // A malformed op-less operation degrades to 'unknown' rather than throwing.
  t.equal(
    parseGroupOperation({ path: 'members', value: members } as unknown as GroupPatchOperation).action,
    'unknown'
  );

  t.end();
});

const userOp = (op: string, path: string, value?: unknown) =>
  parseUserPatchRequest({ op, path, value } as unknown as UserPatchOperation);

tap.test('parseUserPatchRequest recognizes PascalCase "Remove" as a removal', async (t) => {
  // Entra remove: the attribute is marked for deletion (REMOVE_SENTINEL) and the
  // standard-model field is cleared, regardless of op casing.
  for (const op of ['Remove', 'remove']) {
    const { attributes, rawAttributes } = userOp(op, 'name.givenName');
    t.equal(attributes.first_name, '', `${op}: standard field cleared`);
    t.equal(typeof rawAttributes['name.givenName'], 'symbol', `${op}: raw attr marked for removal`);
  }

  // A non-remove op sets the value rather than removing it.
  const { attributes, rawAttributes } = userOp('Replace', 'name.givenName', 'Jane');
  t.equal(attributes.first_name, 'Jane');
  t.equal(rawAttributes['name.givenName'], 'Jane');

  t.end();
});
