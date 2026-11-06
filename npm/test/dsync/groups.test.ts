import { IDirectorySyncController, Directory, DirectorySyncEvent } from '../../src/typings';
import tap from 'tap';
import groups from './data/groups';
import { default as groupsRequest } from './data/group-requests';
import { getFakeDirectory } from './data/directories';
import { jacksonOptions } from '../utils';

let directorySync: IDirectorySyncController;
let directory: Directory;
const fakeDirectory = getFakeDirectory();

tap.before(async () => {
  const jackson = await (await import('../../src/index')).default(jacksonOptions);

  directorySync = jackson.directorySyncController;

  const { data, error } = await directorySync.directories.create(fakeDirectory);

  if (error || !data) {
    tap.fail("Couldn't create a directory");
    return;
  }

  directory = data;
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('Directory groups /', async (t) => {
  t.teardown(async () => {
    await directorySync.directories.delete(directory.id);
  });

  t.test('Directory groups /', async (t) => {
    let createdGroup: any;

    t.beforeEach(async () => {
      // Create a group before each test
      const { data } = await directorySync.requests.handle(groupsRequest.create(directory, groups[0]));

      createdGroup = data;

      // Creating same group again should return 409
      const { status } = await directorySync.requests.handle(groupsRequest.create(directory, groups[0]));

      t.equal(status, 409);
    });

    t.afterEach(async () => {
      // Delete the group after each test
      await directorySync.groups.delete(createdGroup.id);
    });

    t.test('Should be able to create a new group', async (t) => {
      t.ok(createdGroup);
      t.hasStrict(createdGroup, groups[0]);
      t.ok('id' in createdGroup);
    });

    t.test('Should be able to get the group by id', async (t) => {
      const request = groupsRequest.getById(directory, createdGroup.id);

      const { status, data } = await directorySync.requests.handle(request);

      t.ok(data);
      t.equal(status, 200);
      t.hasStrict(data, createdGroup);
      t.hasStrict(data, groups[0]);
    });

    t.test('Should be able to get the group by displayName', async (t) => {
      const request = groupsRequest.filterByDisplayName(directory, createdGroup.displayName);

      const { status, data } = await directorySync.requests.handle(request);

      t.ok(data);
      t.equal(status, 200);
      t.hasStrict(data.Resources[0], createdGroup);
      t.hasStrict(data.Resources[0], groups[0]);
      t.equal(data.Resources.length, 1);
    });

    t.test('Should be able to get all groups', async (t) => {
      const request = groupsRequest.getAll(directory);

      const { status, data } = await directorySync.requests.handle(request);

      t.ok(data);
      t.equal(status, 200);
      t.hasStrict(data.Resources[0], createdGroup);
      t.hasStrict(data.Resources[0], groups[0]);
      t.equal(data.totalResults, 1);
      t.equal(data.Resources[0].members.length, 0);
    });

    t.test('Should be able to update the group name', async (t) => {
      const request = groupsRequest.updateName(directory, createdGroup.id, {
        ...createdGroup,
        displayName: 'Developers Updated',
      });

      const callback = async (event: DirectorySyncEvent) => {
        t.match(event.event, 'group.updated');
        t.match(event.data, { id: createdGroup.id, name: 'Developers Updated' });
      };

      const { status, data } = await directorySync.requests.handle(request, callback);

      t.ok(data);
      t.equal(status, 200);
      t.equal(data.displayName, 'Developers Updated');
    });

    t.test('Should be able to delete a group', async (t) => {
      const request = groupsRequest.deleteById(directory, createdGroup.id);

      const callback = async (event: DirectorySyncEvent) => {
        t.match(event.event, 'group.deleted');
        t.match(event.data, { id: createdGroup.id, name: 'Developers' });
      };

      const { status } = await directorySync.requests.handle(request, callback);

      t.equal(status, 200);

      // Try to get the group
      try {
        await directorySync.requests.handle(groupsRequest.getById(directory, createdGroup.id));
      } catch (e: any) {
        t.equal(e.statusCode, 404);
        t.equal(e.message, `Group with id ${createdGroup.id} not found.`);
      }
    });
  });
});
