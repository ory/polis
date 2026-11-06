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
} from '../../typings';
import { parseGroupOperation } from './utils';
import { sendEvent } from '../utils';
import { isConnectionActive } from '../../controller/utils';

interface DirectoryGroupsParams {
  directories: IDirectoryConfig;
  users: IUsers;
  groups: IGroups;
}

export class DirectoryGroups {
  private directories: IDirectoryConfig;
  private users: IUsers;
  private groups: IGroups;
  private callback: EventCallback | undefined;

  constructor({ directories, users, groups }: DirectoryGroupsParams) {
    this.directories = directories;
    this.users = users;
    this.groups = groups;
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

  public async get(group: Group): Promise<DirectorySyncResponse> {
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

  public async getAll(queryParams: { filter?: string; directoryId: string }): Promise<DirectorySyncResponse> {
    const { filter, directoryId } = queryParams;

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

    return {
      status: 200,
      data: {
        schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
        totalResults: groups ? groups.length : 0,
        itemsPerPage: groups ? groups.length : 0,
        startIndex: 1,
        Resources: groups ? groups.map((group) => group.raw) : [],
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
          return await this.get(group);
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
        });
    }

    return this.respondWithError({ code: 404, message: 'Not found' });
  }
}
