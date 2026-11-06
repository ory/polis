import { admin } from '@googleapis/admin';
import { OAuth2Client } from 'google-auth-library';

import type {
  Directory,
  IDirectoryConfig,
  Group,
  GroupMember,
  IDirectoryProvider,
  JacksonOption,
  PaginationParams,
} from '../../../typings';

interface GoogleProviderParams {
  opts: JacksonOption;
  directories: IDirectoryConfig;
}

export class GoogleProvider implements IDirectoryProvider {
  opts: JacksonOption;
  directories: IDirectoryConfig;
  groupFieldsToExcludeWhenCompare = ['etag'];
  userFieldsToExcludeWhenCompare = ['etag', 'lastLoginTime', 'thumbnailPhotoEtag'];

  constructor({ directories, opts }: GoogleProviderParams) {
    this.opts = opts;
    this.directories = directories;
  }

  createOAuth2Client(directory: Directory) {
    const googleProvider = this.opts.dsync?.providers?.google;

    const authClient = new OAuth2Client(
      googleProvider?.clientId,
      googleProvider?.clientSecret,
      `${this.opts.externalUrl}${googleProvider?.callbackPath}`
    );

    authClient.setCredentials({
      access_token: directory.google_access_token,
      refresh_token: directory.google_refresh_token,
    });

    return authClient;
  }

  async getDirectories() {
    const { data: directories } = await this.directories.filterBy({
      provider: 'google',
    });

    if (!directories || directories.length === 0) {
      return [];
    }

    return directories.filter((directory) => {
      return directory.google_access_token && directory.google_refresh_token;
    });
  }

  async getUsers(directory: Directory, options: PaginationParams | null) {
    const query = {
      maxResults: 200,
      customer: 'my_customer',
    };

    if (options?.pageToken) {
      query['pageToken'] = options.pageToken;
    }

    const googleAdmin = admin({ version: 'directory_v1', auth: this.createOAuth2Client(directory) });

    const response = await googleAdmin.users.list(query);

    if (!response.data.users) {
      return {
        data: [],
        metadata: null,
      };
    }

    const users = response.data.users.map((user) => {
      return {
        id: user.id as string,
        email: user.primaryEmail as string,
        first_name: user.name?.givenName as string,
        last_name: user.name?.familyName as string,
        active: !user.suspended,
        raw: user,
      };
    });

    return {
      data: users,
      metadata: {
        pageToken: response.data.nextPageToken ?? undefined,
        hasNextPage: !!response.data.nextPageToken,
      },
    };
  }

  async getGroups(directory: Directory, options: PaginationParams | null) {
    const googleAdmin = admin({ version: 'directory_v1', auth: this.createOAuth2Client(directory) });

    const query = {
      maxResults: 200,
      customer: 'my_customer',
    };

    if (options?.pageToken) {
      query['pageToken'] = options.pageToken;
    }

    const response = await googleAdmin.groups.list(query);

    if (!response.data.groups) {
      return {
        data: [],
        metadata: null,
      };
    }

    const groups = response.data.groups.map((group) => {
      return {
        id: group.id as string,
        name: group.name as string,
        raw: group,
      };
    });

    return {
      data: groups,
      metadata: {
        pageToken: response.data.nextPageToken as string,
        hasNextPage: !!response.data.nextPageToken,
      },
    };
  }

  async getGroupMembers(directory: Directory, group: Group) {
    const googleAdmin = admin({ version: 'directory_v1', auth: this.createOAuth2Client(directory) });

    const allMembers: GroupMember[] = [];
    const query = {
      maxResults: 200,
      groupKey: group.id,
    };

    let nextPageToken: string | undefined | null = null;

    do {
      if (nextPageToken) {
        query['pageToken'] = nextPageToken;
      }

      const response = await googleAdmin.members.list(query);

      if (!response.data.members) {
        break;
      }

      const members = response.data.members.map((user) => {
        return {
          id: user.id as string,
          raw: user,
        };
      });

      allMembers.push(...members);

      nextPageToken = response.data.nextPageToken;
    } while (nextPageToken);

    return allMembers;
  }
}
