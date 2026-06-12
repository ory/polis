import crypto from 'crypto';
import type {
  Group,
  DirectorySyncResponse,
  Directory,
  DirectorySyncGroupMember,
  DirectorySyncRequest,
  ApiError,
  EventCallback,
  IDirectoryConfig,
  IUsers,
  IGroups,
  GroupPatchOperation,
  JacksonOption,
} from '../../typings';
import { parseGroupOperation } from './utils';
import { sendEvent } from '../utils';
import { isConnectionActive } from '../../controller/utils';

interface DirectoryGroupsParams {
  directories: IDirectoryConfig;
  users: IUsers;
  groups: IGroups;
  opts?: JacksonOption;
}

// Default maximum number of group members returned inline in a SCIM Group
// response. Groups larger than this must be read through the paginated group
// members endpoint to avoid loading an unbounded membership into memory.
// Override with the `dsync.maxInlineGroupMembers` option.
const defaultMaxInlineGroupMembers = 500;

export class DirectoryGroups {
  private directories: IDirectoryConfig;
  private users: IUsers;
  private groups: IGroups;
  private callback: EventCallback | undefined;
  private maxInlineGroupMembers: number;

  constructor({ directories, users, groups, opts }: DirectoryGroupsParams) {
    this.directories = directories;
    this.users = users;
    this.groups = groups;

    const configured = opts?.dsync?.maxInlineGroupMembers;
    this.maxInlineGroupMembers =
      configured !== undefined && Number.isFinite(configured) && configured > 0
        ? configured
        : defaultMaxInlineGroupMembers;
  }

  public async create(directory: Directory, body: any): Promise<DirectorySyncResponse> {
    const { displayName, groupId } = body as { displayName: string; groupId?: string };

    // Check if the group already exists
    const { data: groups } = await this.groups.search(displayName, directory.id);

    if (groups && groups.length > 0) {
      return this.respondWithError({ code: 409, message: 'Group already exists' });
    }

    const { data: group } = await this.groups.create({
      directoryId: directory.id,
      name: displayName,
      id: groupId,
      raw: 'rawAttributes' in body ? body.rawAttributes : { ...body, members: [] },
    });

    await sendEvent('group.created', { directory, group }, this.callback);

    return {
      status: 201,
      data: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        id: group?.id,
        displayName: group?.name,
        members: [],
      },
    };
  }

  public async get(group: Group, includeMembers = false): Promise<DirectorySyncResponse> {
    // Members are omitted by default to avoid loading very large memberships
    // inline. Callers opt in with the `includeMembers` query parameter.
    if (!includeMembers) {
      return {
        status: 200,
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
          id: group.id,
          displayName: group.name,
          members: [],
        },
      };
    }

    const { members, error } = await this.resolveGroupMembers(group);

    if (error) {
      return this.respondWithError(error);
    }

    return {
      status: 200,
      data: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        id: group.id,
        displayName: group.name,
        members,
      },
    };
  }

  public async getAll(queryParams: {
    filter?: string;
    directoryId: string;
    includeMembers?: boolean;
  }): Promise<DirectorySyncResponse> {
    const { filter, directoryId, includeMembers = false } = queryParams;

    let groups: Group[] | null = [];

    if (filter) {
      // Filter by group displayName
      // filter: displayName eq "Developer"
      const { data } = await this.groups.search(filter.split('eq ')[1].replace(/['"]+/g, ''), directoryId);

      groups = data;
    } else {
      // Fetch all the existing group
      const { data } = await this.groups.getAll({ directoryId, pageOffset: undefined, pageLimit: undefined });

      groups = data;
    }

    // By default the stored raw attributes carry an empty members list, because
    // memberships are stored separately from the group. Only enrich each group
    // with its current members when the caller opts in.
    let resources = groups ? groups.map((group) => group.raw) : [];

    if (includeMembers && groups) {
      resources = [];

      for (const group of groups) {
        const { members, error } = await this.resolveGroupMembers(group);

        if (error) {
          return this.respondWithError(error);
        }

        resources.push({ ...group.raw, members });
      }
    }

    return {
      status: 200,
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
        totalResults: groups ? groups.length : 0,
        itemsPerPage: groups ? groups.length : 0,
        startIndex: 1,
        Resources: resources,
      },
    };
  }

  public async patch(directory: Directory, group: Group, body: any): Promise<DirectorySyncResponse> {
    const { Operations } = body as { Operations: GroupPatchOperation[] };

    for (const op of Operations) {
      const operation = parseGroupOperation(op);

      // Add group members
      if (operation.action === 'addGroupMember') {
        await this.addGroupMembers(directory, group, operation.members);
      }

      // Remove group members
      if (operation.action === 'removeGroupMember') {
        await this.removeGroupMembers(directory, group, operation.members);
      }

      // Update group name
      if (operation.action === 'updateGroupName') {
        await this.updateDisplayName(directory, group, {
          displayName: operation.displayName,
        });
      }
    }

    const { data: updatedGroup } = await this.groups.get(group.id);

    return {
      status: 200,
      data: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        id: updatedGroup?.id,
        displayName: updatedGroup?.name,
        members: [],
      },
    };
  }

  public async update(directory: Directory, group: Group, body: any): Promise<DirectorySyncResponse> {
    const updatedGroup = await this.updateDisplayName(directory, group, body);

    return {
      status: 200,
      data: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        id: group.id,
        displayName: updatedGroup.name,
        members: [],
      },
    };
  }

  public async delete(directory: Directory, group: Group): Promise<DirectorySyncResponse> {
    await this.groups.delete(group.id);

    await sendEvent('group.deleted', { directory, group }, this.callback);

    return {
      status: 200,
      data: {},
    };
  }

  // Update group displayName
  public async updateDisplayName(directory: Directory, group: Group, body: any): Promise<Group> {
    const { data: updatedGroup, error } = await this.groups.update(group.id, {
      name: body.displayName,
      raw: 'rawAttributes' in body ? body.rawAttributes : { ...group.raw, ...body },
    });

    if (error || !updatedGroup) {
      throw error;
    }

    await sendEvent('group.updated', { directory, group: updatedGroup }, this.callback);

    return updatedGroup;
  }

  // Fetch the current members of a group as SCIM group members. Memberships are
  // stored separately from the group, so they must be loaded explicitly to
  // populate the `members` attribute in SCIM Group responses.
  //
  // Reads are bounded to `this.maxInlineGroupMembers + 1` members so a group with a
  // very large membership cannot exhaust memory. Groups over the limit return
  // an error directing the caller to the paginated group members endpoint.
  private async resolveGroupMembers(
    group: Group
  ): Promise<{ members: { value: string }[]; error?: undefined } | { members?: undefined; error: ApiError }> {
    // Fast path: stores that support counting (SQL, Mongo) reject oversized
    // groups without reading any member rows.
    const total = await this.groups.getGroupMembersCount(group.id);

    if (total !== undefined && total > this.maxInlineGroupMembers) {
      return { error: this.membersTooLargeError(group) };
    }

    // Walk pages until the membership is exhausted. The store caps the page
    // size, so a single read cannot return the whole membership. Offset-based
    // stores (SQL, Mongo, in-memory) and token-based stores (DynamoDB) are both
    // supported; a page that does not advance ends the walk so a store that
    // ignores the offset cannot loop forever.
    const members: { value: string }[] = [];
    let pageOffset = 0;
    let pageToken: string | undefined;
    let previousFirstId: string | undefined;

    while (true) {
      const usedToken = pageToken !== undefined;

      const response = await this.groups.getGroupMembers({
        groupId: group.id,
        pageOffset,
        pageLimit: this.maxInlineGroupMembers + 1,
        pageToken,
      });

      const rows = response.data ?? [];
      const nextPageToken = (response as { pageToken?: string }).pageToken;

      if (rows.length === 0) {
        break;
      }

      // Guard against a store that ignores the offset and keeps returning the
      // same page, which would otherwise duplicate members or loop forever.
      if (!usedToken && rows[0].user_id === previousFirstId) {
        break;
      }

      previousFirstId = rows[0].user_id;

      for (const member of rows) {
        members.push({ value: member.user_id });
      }

      if (members.length > this.maxInlineGroupMembers) {
        return { error: this.membersTooLargeError(group) };
      }

      if (nextPageToken) {
        // Token-paginated store: continue with the next page token.
        pageToken = nextPageToken;
        pageOffset += rows.length;
        continue;
      }

      if (usedToken) {
        // Token-paginated store with no further pages.
        break;
      }

      // Offset-paginated store: advance to the next page.
      pageOffset += rows.length;
    }

    return { members };
  }

  private membersTooLargeError(group: Group): ApiError {
    return {
      code: 400,
      message: `Group "${group.name}" has more than ${this.maxInlineGroupMembers} members. Retrieve them with the group members endpoint instead.`,
    };
  }

  public async addGroupMembers(
    directory: Directory,
    group: Group,
    members: DirectorySyncGroupMember[] | undefined
  ) {
    if (members === undefined || (members && members.length === 0)) {
      return;
    }

    for (const member of members) {
      if (!(await this.groups.isUserInGroup(group.id, member.value))) {
        await this.groups.addUserToGroup(group.id, member.value);
      }

      const { data: user } = await this.users.get(member.value);

      await sendEvent('group.user_added', { directory, group, user }, this.callback);
    }
  }

  public async removeGroupMembers(
    directory: Directory,
    group: Group,
    members: DirectorySyncGroupMember[] | undefined
  ) {
    if (members === undefined || (members && members.length === 0)) {
      return;
    }

    for (const member of members) {
      await this.groups.removeUserFromGroup(group.id, member.value);

      const { data: user } = await this.users.get(member.value);

      // User may not exist in the directory, so we need to check if the user exists
      if (user) {
        await sendEvent('group.user_removed', { directory, group, user }, this.callback);
      }
    }
  }

  private respondWithError(error: ApiError | null) {
    return {
      status: error ? error.code : 500,
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
        detail: error ? error.message : 'Internal Server Error',
      },
    };
  }

  // Handle the request from the Identity Provider and route it to the appropriate method
  public async handleRequest(
    request: DirectorySyncRequest,
    callback?: EventCallback
  ): Promise<DirectorySyncResponse> {
    const { body, query, resourceId: groupId, directoryId, apiSecret } = request;

    const method = request.method.toUpperCase();

    // Get the directory
    const { data: directory, error } = await this.directories.get(directoryId);

    if (error) {
      return this.respondWithError(error);
    }

    if (!directory) {
      return {
        status: 200,
        data: {},
      };
    }

    if (!isConnectionActive(directory)) {
      return {
        status: 200,
        data: {},
      };
    }

    // Validate the request
    try {
      if (!crypto.timingSafeEqual(Buffer.from(directory.scim.secret), Buffer.from(apiSecret || ''))) {
        return this.respondWithError({ code: 401, message: 'Unauthorized' });
      }
    } catch {
      return this.respondWithError({ code: 401, message: 'Unauthorized' });
    }

    this.callback = callback;

    this.users.setTenantAndProduct(directory.tenant, directory.product);
    this.groups.setTenantAndProduct(directory.tenant, directory.product);

    // Get the group
    const { data: group } = groupId ? await this.groups.get(groupId) : { data: null };

    if (groupId && !group) {
      return this.respondWithError({ code: 404, message: 'Group not found' });
    }

    if (group) {
      switch (method) {
        case 'GET':
          return await this.get(group, query.includeMembers);
        case 'PUT':
          return await this.update(directory, group, body);
        case 'PATCH':
          return await this.patch(directory, group, body);
        case 'DELETE':
          return await this.delete(directory, group);
      }
    }

    switch (method) {
      case 'POST':
        return await this.create(directory, body);
      case 'GET':
        return await this.getAll({
          filter: query.filter,
          directoryId,
          includeMembers: query.includeMembers,
        });
    }

    return this.respondWithError({ code: 404, message: 'Not found' });
  }
}
