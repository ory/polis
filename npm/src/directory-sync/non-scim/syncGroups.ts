import type {
  Directory,
  IGroups,
  Group,
  IRequestHandler,
  DirectorySyncRequest,
  EventCallback,
  IDirectoryProvider,
  PaginationParams,
} from '../../typings';
import { compareAndFindDeletedGroups, isGroupUpdated, toGroupSCIMPayload } from './utils';

interface SyncGroupsParams {
  groupController: IGroups;
  provider: IDirectoryProvider;
  requestHandler: IRequestHandler;
  callback: EventCallback;
  directory: Directory;
}

type HandleRequestParams = Pick<DirectorySyncRequest, 'method' | 'body' | 'resourceId'>;

export class SyncGroups {
  private groupController: IGroups;
  private provider: IDirectoryProvider;
  private requestHandler: IRequestHandler;
  private callback: EventCallback;
  private directory: Directory;

  constructor({ directory, groupController, callback, requestHandler, provider }: SyncGroupsParams) {
    this.groupController = groupController;
    this.provider = provider;
    this.requestHandler = requestHandler;
    this.callback = callback;
    this.directory = directory;
  }

  async sync() {
    const groupsFromProvider: Group[] = [];
    let nextPageOption: PaginationParams | null = null;

    do {
      const { data: groups, metadata } = await this.provider.getGroups(this.directory, nextPageOption);

      if (!groups || groups.length === 0) {
        break;
      }

      // Create or update groups
      for (const group of groups) {
        const { data: existingGroup } = await this.groupController
          .setTenantAndProduct(this.directory.tenant, this.directory.product)
          .get(group.id);

        if (!existingGroup) {
          await this.createGroup(group);
        } else if (isGroupUpdated(existingGroup, group, this.provider.groupFieldsToExcludeWhenCompare)) {
          await this.updateGroup(group);
        }
      }

      // Store groups to compare and delete later
      groupsFromProvider.push(...groups);

      nextPageOption = metadata;
    } while (nextPageOption && nextPageOption.hasNextPage);

    // Delete users that are not in the directory anymore
    const existingGroups = await this.getAllExistingGroups();
    const groupsToDelete = compareAndFindDeletedGroups(existingGroups, groupsFromProvider);

    await this.deleteGroups(groupsToDelete);
  }

  // Get all the existing groups from the Jackson store
  async getAllExistingGroups() {
    const existingGroups: Group[] = [];
    const pageLimit = 500;
    let pageOffset = 0;

    while (true as boolean) {
      const { data: groups } = await this.groupController
        .setTenantAndProduct(this.directory.tenant, this.directory.product)
        .getAll({
          directoryId: this.directory.id,
          pageOffset,
          pageLimit,
        });

      if (!groups || groups.length === 0) {
        break;
      }

      existingGroups.push(...groups);

      if (groups.length < pageLimit) {
        break;
      }

      pageOffset += pageLimit;
    }

    return existingGroups;
  }

  async createGroup(group: Group) {
    await this.handleRequest({
      method: 'POST',
      body: toGroupSCIMPayload(group),
      resourceId: undefined,
    });
  }

  async updateGroup(group: Group) {
    await this.handleRequest({
      method: 'PUT',
      body: toGroupSCIMPayload(group),
      resourceId: group.id,
    });
  }

  async deleteGroups(groups: Group[]) {
    for (const group of groups) {
      await this.handleRequest({
        method: 'DELETE',
        body: toGroupSCIMPayload(group),
        resourceId: group.id,
      });
    }
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
