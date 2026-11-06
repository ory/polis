import { Directory, DirectorySyncEvent, DirectorySyncEventType, Group, User } from '../../typings';

const transformUser = (user: User): User => {
  return {
    id: user.id,
    first_name: user.first_name,
    last_name: user.last_name,
    email: user.email,
    active: user.active,
    ...('roles' in user ? { roles: user.roles } : undefined),
    raw: user.raw,
  };
};

const transformGroup = (group: Group): Group => {
  return {
    id: group.id,
    name: group.name,
    raw: group.raw,
  };
};

const transformUserGroup = (user: User, group: Group): User & { group: Group } => {
  return {
    ...transformUser(user),
    group: transformGroup(group),
  };
};

export const transformEventPayload = (
  event: DirectorySyncEventType,
  payload: { directory: Directory; group?: Group | null; user?: User | null }
) => {
  const { directory, group, user } = payload;
  const { tenant, product, id: directory_id } = directory;

  const eventPayload = {
    event,
    tenant,
    product,
    directory_id,
  };

  // User events
  if (['user.created', 'user.updated', 'user.deleted'].includes(event) && user) {
    eventPayload['data'] = transformUser(user);
  }

  // Group events
  if (['group.created', 'group.updated', 'group.deleted'].includes(event) && group) {
    eventPayload['data'] = transformGroup(group);
  }

  // Group membership events
  if (['group.user_added', 'group.user_removed'].includes(event) && user && group) {
    eventPayload['data'] = transformUserGroup(user, group);
  }

  return eventPayload as DirectorySyncEvent;
};
