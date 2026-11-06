import _ from 'lodash';

import type {
  Directory,
  IGroups,
  Group,
  IRequestHandler,
  DirectorySyncRequest,
  EventCallback,
  IDirectoryProvider,
  PaginationParams,
  GroupMembership,
} from '../../typings';
import {
  compareAndFindDeletedMembers,
  compareAndFindNewMembers,
  toGroupMembershipSCIMPayload,
} from './utils';

interface SyncGroupMembersParams {
  groupController: IGroups;
  provider: IDirectoryProvider;
  requestHandler: IRequestHandler;
  callback: EventCallback;
  directory: Directory;
}

type HandleRequestParams = Pick<DirectorySyncRequest, 'method' | 'body' | 'resourceId'>;

export class SyncGroupMembers {
  private groupController: IGroups;
  private provider: IDirectoryProvider;
  private requestHandler: IRequestHandler;
  private callback: EventCallback;
  private directory: Directory;

  constructor({ directory, groupController, requestHandler, provider, callback }: SyncGroupMembersParams) {
    this.groupController = groupController;
    this.provider = provider;
    this.requestHandler = requestHandler;
    this.callback = callback;
    this.directory = directory;
  }

  async sync() {
    let nextPageOption: PaginationParams | null = null;

    do {
      const { data: groups, metadata } = await this.provider.getGroups(this.directory, nextPageOption);

      if (!groups || groups.length === 0) {
        break;
      }

      for (const group of groups) {
        const membersFromDB = await this.getAllExistingMembers(group);
        const membersFromProvider = await this.provider.getGroupMembers(this.directory, group);

        const idsFromDB = _.map(membersFromDB, 'user_id');
        const idsFromProvider = _.map(membersFromProvider, 'id');

        const deletedMembers = compareAndFindDeletedMembers(idsFromDB, idsFromProvider);
        const newMembers = compareAndFindNewMembers(idsFromDB, idsFromProvider);

        if (deletedMembers && deletedMembers.length > 0) {
          await this.deleteMembers(group, deletedMembers);
        }

        if (newMembers && newMembers.length > 0) {
          await this.addMembers(group, newMembers);
        }
      }

      nextPageOption = metadata;
    } while (nextPageOption && nextPageOption.hasNextPage);
  }

  // Get all existing members for a group from the Jackson store
  async getAllExistingMembers(group: Group) {
    const existingMembers: Pick<GroupMembership, 'user_id'>[] = [];
    const pageLimit = 500;
    let pageOffset = 0;

    while (true as boolean) {
      const { data: members } = await this.groupController
        .setTenantAndProduct(this.directory.tenant, this.directory.product)
        .getGroupMembers({
          groupId: group.id,
          pageOffset,
          pageLimit,
        });

      if (!members || members.length === 0) {
        break;
      }

      existingMembers.push(...members);

      if (members.length < pageLimit) {
        break;
      }

      pageOffset += pageLimit;
    }

    return existingMembers;
  }

  async addMembers(group: Group, memberIds: string[]) {
    await this.handleRequest({
      method: 'PATCH',
      body: toGroupMembershipSCIMPayload(memberIds, 'add'),
      resourceId: group.id,
    });
  }

  async deleteMembers(group: Group, memberIds: string[]) {
    await this.handleRequest({
      method: 'PATCH',
      body: toGroupMembershipSCIMPayload(memberIds, 'remove'),
      resourceId: group.id,
    });
  }

  async handleRequest(payload: HandleRequestParams) {
    const request: DirectorySyncRequest = {
      query: {},
      body: payload.body,
      resourceType: 'groups',
      method: payload.method,
      directoryId: this.directory.id,
      apiSecret: this.directory.scim.secret,
      resourceId: payload.resourceId,
    };

    await this.requestHandler.handle(request, this.callback);
  }
}
