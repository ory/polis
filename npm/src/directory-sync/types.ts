import directorySync from '.';
import { DirectoryConfig } from './scim/DirectoryConfig';
import { DirectoryGroups } from './scim/DirectoryGroups';
import { DirectoryUsers } from './scim/DirectoryUsers';
import { Users } from './scim/Users';
import { Groups } from './scim/Groups';
import { WebhookEventsLogger } from './scim/WebhookEventsLogger';
import { ApiError } from '../typings';
import { RequestHandler } from './request';
import { EventProcessor } from './batch-events/queue';
import { CronLock as Lock } from '../cron/lock';

export type IDirectorySyncController = Awaited<ReturnType<typeof directorySync>>;
export type IDirectoryConfig = InstanceType<typeof DirectoryConfig>;
export type IDirectoryGroups = InstanceType<typeof DirectoryGroups>;
export type IDirectoryUsers = InstanceType<typeof DirectoryUsers>;
export type IUsers = InstanceType<typeof Users>;
export type IGroups = InstanceType<typeof Groups>;
export type IWebhookEventsLogger = InstanceType<typeof WebhookEventsLogger>;
export type IRequestHandler = InstanceType<typeof RequestHandler>;
export type IEventProcessor = InstanceType<typeof EventProcessor>;
export type CronLock = InstanceType<typeof Lock>;

export type DirectorySyncEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'group.created'
  | 'group.updated'
  | 'group.deleted'
  | 'group.user_added'
  | 'group.user_removed';

export enum DirectorySyncProviders {
  'azure-scim-v2' = 'Entra ID SCIM v2.0',
  'onelogin-scim-v2' = 'OneLogin SCIM v2.0',
  'okta-scim-v2' = 'Okta SCIM v2.0',
  'jumpcloud-scim-v2' = 'JumpCloud v2.0',
  'generic-scim-v2' = 'Generic SCIM v2.0',
  'google' = 'Google',
}

export type DirectoryType = keyof typeof DirectorySyncProviders;

export type Directory = {
  id: string;
  name: string;
  tenant: string;
  product: string;
  type: DirectoryType;
  log_webhook_events: boolean;
  scim: {
    path: string;
    endpoint?: string;
    secret: string;
  };
  webhook: {
    endpoint: string;
    secret: string;
  };
  deactivated?: boolean;
  google_access_token?: string;
  google_refresh_token?: string;
  google_authorization_url?: string;
};

export type DirectorySyncGroupMember = { value: string; email?: string };

export type DirectorySyncResponse = {
  status: number;
  data?: any;
};

export interface Events {
  handle(event: DirectorySyncEvent): Promise<void>;
}

export interface DirectorySyncRequest {
  method: string; //'POST' | 'PUT' | 'DELETE' | 'GET' | 'PATCH';
  body: any | undefined;
  directoryId: Directory['id'];
  resourceType: string; //'users' | 'groups';
  resourceId: string | undefined;
  apiSecret: string | null;
  query: {
    count?: number;
    startIndex?: number;
    filter?: string;
  };
}

export type DirectorySyncEventData = User | Group | UserWithGroup;

export interface DirectorySyncEvent {
  directory_id: Directory['id'];
  event: DirectorySyncEventType;
  data: DirectorySyncEventData;
  tenant: string;
  product: string;
}

export interface WebhookEventLog {
  id: string;
  webhook_endpoint: string;
  created_at: Date;
  status_code?: number;
  delivered?: boolean;
  payload: DirectorySyncEvent | DirectorySyncEvent[];
}

export type User = {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  active: boolean;
  roles?: string[];
  raw?: any;
};

export type Group = {
  id: string;
  name: string;
  raw?: any;
};

export type GroupMember = {
  id: string;
  raw?: any;
};

export type UserWithGroup = User & { group: Group };

export type PaginationParams = {
  pageOffset?: number;
  pageLimit?: number;
  pageToken?: string;
  hasNextPage?: boolean;
};

export type UserPatchOperation = {
  op: 'replace' | 'add';
  path?: string;
  value:
    | boolean
    | {
        active: boolean;
      }
    | {
        'name.givenName': string;
      }
    | {
        'name.familyName': string;
      }
    | {
        'emails[type eq "work"].value': string;
      }
    | {
        [key: string]: string | boolean;
      };
};

export type GroupPatchOperation = {
  op: 'add' | 'remove' | 'replace';
  path?: 'members' | 'displayName';
  value:
    | string
    | {
        value: string;
        display?: string;
      }[];
};

export type GroupMembership = {
  id: string;
  group_id: string;
  user_id: string;
};

export type Response<T> = { data: T; error: null; pageToken?: string } | { data: null; error: ApiError };

export type EventCallback = (event: DirectorySyncEvent) => Promise<void>;

export interface IDirectoryProvider {
  /**
   * Fields to exclude from the user payload while comparing the user to find if it is updated
   */
  userFieldsToExcludeWhenCompare?: string[];

  /**
   * Fields to exclude from the group payload while comparing the group to find if it is updated
   */
  groupFieldsToExcludeWhenCompare?: string[];

  /**
   * Get all directories for the provider
   */
  getDirectories(): Promise<Directory[]>;

  /**
   * Get all users for a directory
   * @param directory
   * @param options
   */
  getUsers(
    directory: Directory,
    options: PaginationParams | null
  ): Promise<{ data: User[]; metadata: PaginationParams | null }>;

  /**
   * Get all groups for a directory
   * @param directory
   * @param options
   */
  getGroups(
    directory: Directory,
    options: PaginationParams | null
  ): Promise<{ data: Group[]; metadata: PaginationParams | null }>;

  /**
   * Get all members of a group
   * @param directory
   * @param group
   */
  getGroupMembers(directory: Directory, group: Group): Promise<GroupMember[]>;
}
