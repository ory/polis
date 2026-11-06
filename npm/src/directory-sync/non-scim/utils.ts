import _ from 'lodash';
import crypto from 'crypto';

import type { User, Group } from '../../typings';

export const toUserSCIMPayload = (user: User) => {
  return {
    userName: user.email,
    name: {
      givenName: user.first_name,
      familyName: user.last_name,
    },
    emails: [
      {
        primary: true,
        value: user.email,
        type: 'work',
      },
    ],
    userId: user.id,
    active: user.active,
    rawAttributes: user.raw,
  };
};

export const toGroupSCIMPayload = (group: Group) => {
  return {
    displayName: group.name,
    groupId: group.id,
    rawAttributes: group.raw,
  };
};

export const toGroupMembershipSCIMPayload = (memberIds: string[], operation: 'add' | 'remove') => {
  const memberValues = memberIds.map((memberId) => {
    return {
      value: memberId,
    };
  });

  return {
    Operations: [
      {
        op: operation,
        path: 'members',
        value: memberValues,
      },
    ],
  };
};

export const isUserUpdated = (
  existingUser: User,
  userFromProvider: User,
  ignoreFields: string[] | undefined
) => {
  const copyOfExistingUser = _.cloneDeep(existingUser);
  const copyOfUserFromProvider = _.cloneDeep(userFromProvider);

  if (ignoreFields && ignoreFields.length > 0) {
    ignoreFields.forEach((field) => {
      _.unset(copyOfExistingUser.raw, field);
      _.unset(copyOfUserFromProvider.raw, field);
    });
  }

  return getObjectHash(copyOfExistingUser.raw) !== getObjectHash(copyOfUserFromProvider.raw);
};

export const isGroupUpdated = (
  existingGroup: Group,
  groupFromProvider: Group,
  ignoreFields: string[] | undefined
) => {
  const copyOfExistingGroup = _.cloneDeep(existingGroup);
  const copyOfGroupFromProvider = _.cloneDeep(groupFromProvider);

  if (ignoreFields && ignoreFields.length > 0) {
    ignoreFields.forEach((field) => {
      _.unset(copyOfExistingGroup.raw, field);
      _.unset(copyOfGroupFromProvider.raw, field);
    });
  }

  return getObjectHash(copyOfExistingGroup.raw) !== getObjectHash(copyOfGroupFromProvider.raw);
};

export const compareAndFindDeletedGroups = (existingGroups: Group[] | null, groups: Group[]) => {
  if (!existingGroups || existingGroups.length === 0) {
    return [];
  }

  const groupsToDelete = existingGroups.filter((existingGroup) => {
    return !groups.some((group) => group.id === existingGroup.id);
  });

  return groupsToDelete;
};

export const compareAndFindDeletedUsers = (existingUsers: User[] | null, users: User[]) => {
  if (!existingUsers || existingUsers.length === 0) {
    return [];
  }

  const usersToDelete = existingUsers.filter((existingUser) => {
    return !users.some((user) => user.id === existingUser.id);
  });

  return usersToDelete;
};

export const compareAndFindDeletedMembers = (idsFromDB: string[], idsFromProvider: string[]) => {
  return idsFromDB.filter((userId) => !idsFromProvider.includes(userId));
};

export const compareAndFindNewMembers = (idsFromDB: string[], idsFromProvider: string[]) => {
  return idsFromProvider.filter((userId) => !idsFromDB.includes(userId));
};

const normalizeObject = (obj: any) => {
  if (_.isArray(obj)) {
    return obj.map(normalizeObject);
  } else if (_.isObject(obj)) {
    const sortedKeys = _.sortBy(Object.keys(obj));
    return _.fromPairs(sortedKeys.map((key) => [key, normalizeObject(obj[key])]));
  } else {
    return obj;
  }
};

const getObjectHash = (obj: any) => {
  const normalizedObj = normalizeObject(obj);
  const hash = crypto.createHash('sha1');

  hash.update(JSON.stringify(normalizedObj));

  return hash.digest('hex');
};
