import { IDirectorySyncController, Directory } from '../../src/typings';
import tap from 'tap';
import users from './data/users';
import requests from './data/user-requests';
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

tap.test('Directory users /', async (t) => {
  t.teardown(async () => {
    await directorySync.directories.delete(directory.id);
  });

  t.test('Directory users /', async (t) => {
    let createdUser: any;

    t.beforeEach(async () => {
      // Create a user before each test
      const { data } = await directorySync.requests.handle(requests.create(directory, users[0]));

      createdUser = data;

      // Creating same user again should return 409
      const { status } = await directorySync.requests.handle(requests.create(directory, users[0]));

      t.equal(status, 409);
    });

    t.afterEach(async () => {
      // Delete the user after each test
      await directorySync.users.delete(createdUser.id);
    });

    t.test('Should be able to get the user by userName', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.filterByUsername(directory, createdUser.userName)
      );

      t.ok(data);
      t.equal(status, 200);
      t.hasStrict(data.Resources[0], createdUser);
      t.hasStrict(data.Resources[0], users[0]);
    });

    t.test('Should be able to get the user by id', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.hasStrict(data, users[0]);
    });

    t.test('Should be able to update the user using PUT request', async (t) => {
      const toUpdate = {
        ...users[0],
        name: {
          givenName: 'Jackson Updated',
          familyName: 'M',
        },
        city: 'New York',
        roles: ['viewer', 'editor'],
      };

      const { status, data: updatedUser } = await directorySync.requests.handle(
        requests.updateById(directory, createdUser.id, toUpdate)
      );

      t.ok(updatedUser);
      t.equal(status, 200);
      t.hasStrict(updatedUser, toUpdate);
      t.match(updatedUser.city, toUpdate.city);
      t.match(updatedUser.roles, toUpdate.roles);

      // Make sure the user was updated
      const { data: user } = await directorySync.requests.handle(requests.getById(directory, createdUser.id));

      t.ok(user);
      t.hasStrict(user, toUpdate);
      t.match(user.city, toUpdate.city);
      t.match(user.roles, toUpdate.roles);
    });

    t.test('Should be able to delete the user using PATCH request', async (t) => {
      const toUpdate = {
        ...users[0],
        active: false,
      };

      const { status, data } = await directorySync.requests.handle(
        requests.updateOperationById(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.hasStrict(data, toUpdate);
    });

    t.test('should be able to update the user with multi-valued properties', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.multiValuedProperties(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.equal(data.active, false);
      t.equal(data.name.givenName, 'David');
      t.equal(data.name.familyName, 'Jones');
    });

    t.test('Should be able to update the custom user attributes', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.customAttributes(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.equal(data.companyName, 'Ory');
      t.equal(data.address.streetAddress, '123 Main St');
    });

    t.test('Should be able to fetch all users', async (t) => {
      const { status, data } = await directorySync.requests.handle(requests.getAll(directory));

      t.ok(data);
      t.equal(status, 200);
      t.ok(data.Resources);
      t.equal(data.Resources.length, 1);
      t.hasStrict(data.Resources[0], users[0]);
      t.equal(data.totalResults, 1);
    });

    t.test('Should be able to delete the user', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.deleteById(directory, createdUser.id)
      );

      t.equal(status, 200);
      t.ok(data);
      t.strictSame(data, createdUser);

      // Make sure the user was deleted
      const { data: user } = await directorySync.requests.handle(
        requests.filterByUsername(directory, createdUser.userName)
      );

      t.hasStrict(user.Resources, []);
      t.hasStrict(user.totalResults, 0);
    });

    t.test('Should be able to delete all users using deleteAll() method', async (t) => {
      directorySync.users.setTenantAndProduct(directory.tenant, directory.product);

      await directorySync.users.deleteAll(directory.id);

      // Make sure all the user was deleted
      const { data: users } = await directorySync.users.getAll();

      t.equal(users?.length, 0);
    });

    t.test('Should be able to add & remove roles to the user', async (t) => {
      // Create a user with no roles
      const { data: createdUser } = await directorySync.requests.handle(
        requests.create(directory, users[1]),
        async (event) => {
          t.equal(event.event, 'user.created');
          t.notOk('roles' in event.data);
        }
      );

      // Add roles to the user
      await directorySync.requests.handle(
        requests.updateById(directory, createdUser.id, {
          ...users[1],
          roles: ['viewer'],
        }),
        async (event) => {
          t.equal(event.event, 'user.updated');
          t.equal(
            'roles' in event.data && event.data.roles?.every((role: string) => ['viewer'].includes(role)),
            true
          );
        }
      );

      // Update the user with new roles
      await directorySync.requests.handle(
        requests.updateById(directory, createdUser.id, {
          ...users[1],
          roles: 'viewer,editor',
        }),
        async (event) => {
          t.equal(event.event, 'user.updated');
          t.equal(
            'roles' in event.data &&
              event.data.roles?.every((role: string) => ['viewer', 'editor'].includes(role)),
            true
          );
        }
      );

      // Remove roles from the user
      await directorySync.requests.handle(
        requests.updateById(directory, createdUser.id, users[1]),
        async (event) => {
          t.equal(event.event, 'user.updated');
          t.ok(!('roles' in event.data));
        }
      );
    });

    // Activate and deactivate user
    t.test('Should be able to activate and deactivate the user', async (t) => {
      // Deactivate the user
      await directorySync.requests.handle(
        requests.updateById(directory, createdUser.id, {
          ...users[1],
          active: false,
        }),
        async (event) => {
          t.equal(event.event, 'user.updated');
          t.ok('active' in event.data && event.data.active === false);
        }
      );

      // Activate the user
      await directorySync.requests.handle(
        requests.updateById(directory, createdUser.id, {
          ...users[1],
          active: true,
        }),
        async (event) => {
          t.equal(event.event, 'user.updated');
          t.ok('active' in event.data && event.data.active === true);
        }
      );
    });
  });
});
