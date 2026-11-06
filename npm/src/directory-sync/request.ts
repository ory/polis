import type {
  DirectorySyncResponse,
  IDirectoryGroups,
  IDirectoryUsers,
  EventCallback,
  DirectorySyncRequest,
} from '../typings';

interface RequestHandlerParams {
  directoryUsers: IDirectoryUsers;
  directoryGroups: IDirectoryGroups;
  eventCallback: EventCallback;
}

export class RequestHandler {
  private directoryUsers: IDirectoryUsers;
  private directoryGroups: IDirectoryGroups;
  private eventCallback: EventCallback;

  constructor({ directoryUsers, directoryGroups, eventCallback }: RequestHandlerParams) {
    this.directoryUsers = directoryUsers;
    this.directoryGroups = directoryGroups;
    this.eventCallback = eventCallback;
  }

  async handle(request: DirectorySyncRequest, callback?: EventCallback): Promise<DirectorySyncResponse> {
    const resourceType = request.resourceType.toLowerCase();

    if (resourceType === 'users') {
      return await this.directoryUsers.handleRequest(request, callback || this.eventCallback);
    } else if (resourceType === 'groups') {
      return await this.directoryGroups.handleRequest(request, callback || this.eventCallback);
    }

    return { status: 404, data: {} };
  }
}
