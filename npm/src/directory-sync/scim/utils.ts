import _ from 'lodash';

import { DirectorySyncProviders } from '../../typings';
import type { DirectoryType, User, UserPatchOperation, GroupPatchOperation } from '../../typings';

// Sentinel symbol to mark attributes for removal in updateRawUserAttributes.
const REMOVE_SENTINEL = Symbol(`remove_attribute_${crypto.randomUUID()}`);

export const indexNames = {
  directoryIdUsername: 'directoryIdUsername',
  directoryIdDisplayname: 'directoryIdDisplayname',
  directoryId: 'directoryId',
  groupId: 'groupId',
};

const parseUserRoles = (roles: string | string[]) => {
  if (typeof roles === 'string') {
    return roles.split(',');
  }

  return roles;
};

export const parseGroupOperation = (operation: GroupPatchOperation) => {
  const { path, value } = operation;
  // Microsoft Entra sends PascalCase ops ("Add"/"Remove"/"Replace") unless the
  // tenant enables the aadOptscim062020 flag, so compare case-insensitively.
  const op = operation.op?.toLowerCase();

  if (path === 'members' && typeof value == 'object') {
    if (op === 'add') {
      return {
        action: 'addGroupMember',
        members: value,
      };
    }

    if (op === 'remove') {
      return {
        action: 'removeGroupMember',
        members: value,
      };
    }
  }

  if (path && path.startsWith('members[value eq')) {
    if (op === 'remove') {
      return {
        action: 'removeGroupMember',
        members: [{ value: path.split('"')[1] }],
      };
    }
  }

  // Update group name
  if (op === 'replace') {
    if (path == 'displayName' && typeof value == 'string') {
      return {
        action: 'updateGroupName',
        displayName: value,
      };
    } else if (typeof value == 'object' && 'displayName' in value) {
      return {
        action: 'updateGroupName',
        displayName: value.displayName,
      };
    }
  }

  return {
    action: 'unknown',
  };
};

// List of directory sync providers
// TODO: Fix the return type
export const getDirectorySyncProviders = (): { [K: string]: string } => {
  return Object.entries(DirectorySyncProviders).reduce((acc, [key, value]) => {
    acc[key] = value;
    return acc;
  }, {});
};

// Parse the PATCH request body and return the user attributes (both standard and custom)
export const parseUserPatchRequest = (operation: UserPatchOperation) => {
  const { value, path } = operation;
  // Entra sends PascalCase ops (e.g. "Remove") unless aadOptscim062020 is set;
  // normalize so removals aren't misread as sets. See parseGroupOperation above.
  const op = operation.op?.toLowerCase();

  const attributes: Partial<User> = {};
  const rawAttributes = {};

  const attributesMap = {
    active: 'active',
    'name.givenName': 'first_name',
    'name.familyName': 'last_name',
    'emails[type eq "work"].value': 'email',
  };

  // Handle "remove" operations: mark attributes for deletion
  if (op === 'remove' && path) {
    rawAttributes[path] = REMOVE_SENTINEL;

    // Propagate removal to standard user model attributes
    if (path in attributesMap) {
      attributes[attributesMap[path]] = '';
    }

    return {
      attributes,
      rawAttributes,
    };
  }

  // If there is a path, then the value is the value
  // For example { path: "active", value: true }
  if (path) {
    if (path in attributesMap) {
      attributes[attributesMap[path]] = value;
    }

    rawAttributes[path] = value;
  }

  // If there is no path, then the value can be an object with multiple attributes
  // For example { value: { active: true, "name.familyName": "John" } }
  else if (typeof value === 'object') {
    for (const attribute of Object.keys(value)) {
      if (attribute in attributesMap) {
        attributes[attributesMap[attribute]] = value[attribute];
      }

      rawAttributes[attribute] = value[attribute];
    }
  }

  return {
    attributes,
    rawAttributes,
  };
};

// Extract standard attributes from the user body
export const extractStandardUserAttributes = (body: any) => {
  const { name, emails, userName, active, userId, roles } = body as {
    name?: { givenName: string; familyName: string };
    emails?: { value: string }[];
    userName: string;
    active: boolean;
    userId?: string;
    roles?: string | string[];
  };

  const userAttributes: Omit<User, 'raw'> = {
    first_name: name && 'givenName' in name ? name.givenName : '',
    last_name: name && 'familyName' in name ? name.familyName : '',
    email: emails && emails.length > 0 ? emails[0].value : userName,
    active: 'active' in body ? active : true,
    id: userId || '', // For non-SCIM providers, the id will exist in the body
  };

  if (roles) {
    userAttributes['roles'] = parseUserRoles(roles);
  }

  return userAttributes;
};

// Match SCIM filter paths with a sub-attribute: `phoneNumbers[type eq "work"].value`
const SCIM_FILTER_SUB_ATTR_RE = /^(\w+)\[(\w+)\s+eq\s+"([^"]+)"\]\.(\w+)$/;

// Match SCIM filter paths without a sub-attribute: `phoneNumbers[type eq "work"]`
const SCIM_FILTER_RE = /^(\w+)\[(\w+)\s+eq\s+"([^"]+)"\]$/;

// Resolve a SCIM filter path like `phoneNumbers[type eq "work"].value` to a
// lodash-compatible path like `["phoneNumbers", 0, "value"]`. Returns false for
// non-filter paths so the caller can fall back to plain _.set.
const applySCIMFilterUpdate = (raw: any, path: string, value: any): boolean => {
  const match = path.match(SCIM_FILTER_SUB_ATTR_RE);
  if (!match) {
    return false;
  }

  const [, attribute, filterAttr, filterValue, subAttribute] = match;

  let arr = _.get(raw, attribute);
  if (!Array.isArray(arr)) {
    _.set(raw, attribute, []);
    arr = _.get(raw, attribute);
    // _.set silently refuses writes to unsafe paths like __proto__
    if (!Array.isArray(arr)) {
      return false;
    }
  }

  let idx = arr.findIndex((el: any) => el[filterAttr] === filterValue);
  if (idx < 0) {
    idx = arr.length;
    arr.push({ [filterAttr]: filterValue });
  }

  _.set(arr, [idx, subAttribute], value);

  return true;
};

// Remove matching entries from a multi-valued attribute using a SCIM filter path.
// Handles two forms:
//   - `attr[filter]`         → remove entire matching array entries
//   - `attr[filter].subAttr` → unset only the sub-attribute from matching entries
// Returns false for non-filter paths so the caller can fall back to _.unset.
const removeSCIMFilterPath = (raw: any, path: string): boolean => {
  // Try sub-attribute form first: phoneNumbers[type eq "work"].value
  const subMatch = path.match(SCIM_FILTER_SUB_ATTR_RE);
  if (subMatch) {
    const [, attribute, filterAttr, filterValue, subAttribute] = subMatch;
    const arr = _.get(raw, attribute);
    if (!Array.isArray(arr)) {
      return true; // Nothing to remove — already absent
    }

    for (const el of arr) {
      if (el[filterAttr] === filterValue) {
        delete el[subAttribute];
      }
    }
    return true;
  }

  // Try whole-entry form: phoneNumbers[type eq "work"]
  const match = path.match(SCIM_FILTER_RE);
  if (match) {
    const [, attribute, filterAttr, filterValue] = match;
    const arr = _.get(raw, attribute);
    if (!Array.isArray(arr)) {
      return true; // Nothing to remove — already absent
    }

    _.set(
      raw,
      attribute,
      arr.filter((el: any) => el[filterAttr] !== filterValue)
    );
    return true;
  }

  return false;
};

// Update raw user attributes
export const updateRawUserAttributes = (raw, attributes) => {
  const keys = Object.keys(attributes);

  if (keys.length === 0) {
    return raw;
  }

  for (const key of keys) {
    const value = attributes[key];

    // Handle remove operations (value is the sentinel from parseUserPatchRequest)
    if (value === REMOVE_SENTINEL) {
      if (key.startsWith('urn:')) {
        // If the full key is a top-level property, delete it directly.
        // e.g. "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        if (key in raw) {
          delete raw[key];
        } else {
          // Path format: "urn:...:User:attribute" — remove the attribute from the schema object.
          const i = key.lastIndexOf(':');
          const urn = key.substring(0, i);
          const attrName = key.substring(i + 1);
          if (raw[urn] && typeof raw[urn] === 'object') {
            // If the attribute contains a SCIM filter (e.g. "roles[value eq ...]"),
            // delegate to removeSCIMFilterPath scoped to the schema sub-object.
            if (!removeSCIMFilterPath(raw[urn], attrName)) {
              delete raw[urn][attrName];
            }
          }
        }
      } else if (!removeSCIMFilterPath(raw, key)) {
        _.unset(raw, key);
      }
      continue;
    }

    if (applySCIMFilterUpdate(raw, key, value)) {
      continue;
    }

    // URN keys (e.g. "urn:...:enterprise:2.0:User") contain dots that lodash
    // _.set would interpret as nested path separators, mangling the key.
    // Use direct property access instead.
    if (key.startsWith('urn:')) {
      if (typeof value === 'object' && value !== null) {
        // No-path format: key is the schema URN, value is an attribute object.
        raw[key] = { ...(raw[key] || {}), ...value };
      } else {
        // Path format: "schemaUrn:attribute" — split at last colon.
        const i = key.lastIndexOf(':');
        const urn = key.substring(0, i);
        raw[urn] = raw[urn] && typeof raw[urn] === 'object' ? raw[urn] : {};
        raw[urn][key.substring(i + 1)] = value;
      }
      continue;
    }

    _.set(raw, key, value);
  }

  return raw;
};

export const isSCIMEnabledProvider = (type: DirectoryType) => {
  return type !== 'google';
};
