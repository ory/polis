import type {
  Directory,
  User,
  IUsers,
  IRequestHandler,
  DirectorySyncRequest,
  EventCallback,
  IDirectoryProvider,
  PaginationParams,
} from '../../typings';
import { compareAndFindDeletedUsers, isUserUpdated, toUserSCIMPayload } from './utils';

interface SyncUserParams {
  directory: Directory;
  userController: IUsers;
  callback: EventCallback;
  provider: IDirectoryProvider;
  requestHandler: IRequestHandler;
}

type HandleRequestParams = Pick<DirectorySyncRequest, 'method' | 'body' | 'resourceId'>;

export class SyncUsers {
  private directory: Directory;
  private userController: IUsers;
  private callback: EventCallback;
  private provider: IDirectoryProvider;
  private requestHandler: IRequestHandler;

  constructor({ directory, userController, callback, provider, requestHandler }: SyncUserParams) {
    this.callback = callback;
    this.provider = provider;
    this.directory = directory;
    this.requestHandler = requestHandler;
    this.userController = userController;
  }

  async sync() {
    const usersFromProvider: User[] = [];
    let nextPageOption: PaginationParams | null = null;

    do {
      const { data: users, metadata } = await this.provider.getUsers(this.directory, nextPageOption);

      if (users.length === 0) {
        break;
      }

      // Create or update users
      for (const user of users) {
        const { data: existingUser } = await this.userController
          .setTenantAndProduct(this.directory.tenant, this.directory.product)
          .get(user.id);

        if (!existingUser) {
          await this.createUser(user);
        } else if (isUserUpdated(existingUser, user, this.provider.userFieldsToExcludeWhenCompare)) {
          await this.updateUser(user);
        }
      }

      // Store users to compare and delete later
      usersFromProvider.push(...users);

      nextPageOption = metadata;
    } while (nextPageOption && nextPageOption.hasNextPage);

    // Delete users that are not in the directory anymore
    const existingUsers = await this.getAllExistingUsers();
    const usersToDelete = compareAndFindDeletedUsers(existingUsers, usersFromProvider);

    await this.deleteUsers(usersToDelete);
  }

  // Get all the existing users from the Jackson store
  async getAllExistingUsers() {
    const existingUsers: User[] = [];
    const pageLimit = 500;
    let pageOffset = 0;

    while (true as boolean) {
      const { data: users } = await this.userController
        .setTenantAndProduct(this.directory.tenant, this.directory.product)
        .getAll({
          directoryId: this.directory.id,
          pageOffset,
          pageLimit,
        });

      if (!users || users.length === 0) {
        break;
      }

      existingUsers.push(...users);

      if (users.length < pageLimit) {
        break;
      }

      pageOffset += pageLimit;
    }

    return existingUsers;
  }

  async createUser(user: User) {
    await this.handleRequest({
      method: 'POST',
      body: toUserSCIMPayload(user),
      resourceId: undefined,
    });
  }

  async updateUser(user: User) {
    await this.handleRequest({
      method: 'PUT',
      body: toUserSCIMPayload(user),
      resourceId: user.id,
    });
  }

  async deleteUsers(users: User[]) {
    for (const user of users) {
      await this.handleRequest({
        method: 'DELETE',
        body: toUserSCIMPayload(user),
        resourceId: user.id,
      });
    }
  }

  async handleRequest(payload: HandleRequestParams) {
    const request: DirectorySyncRequest = {
      query: {},
      body: payload.body,
      resourceType: 'users',
      method: payload.method,
      directoryId: this.directory.id,
      apiSecret: this.directory.scim.secret,
      resourceId: payload.resourceId,
    };

    await this.requestHandler.handle(request, this.callback);
  }
}
