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

    t.test('Should remove custom attributes when PATCH uses op: "remove"', async (t) => {
      // First, set some custom attributes
      const { status: setStatus, data: setData } = await directorySync.requests.handle(
        requests.customAttributes(directory, createdUser.id)
      );

      t.equal(setStatus, 200);
      t.equal(setData.companyName, 'Ory');
      t.equal(setData.address.streetAddress, '123 Main St');

      // Now remove them using op: "remove"
      const { status, data } = await directorySync.requests.handle(
        requests.removeCustomAttributes(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.notOk(data.companyName, 'companyName should be removed');
      t.notOk(data.address?.streetAddress, 'address.streetAddress should be removed');

      // Verify the removal persists when fetching the user
      const { data: fetchedUser } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.notOk(fetchedUser.companyName, 'companyName should still be removed after re-fetch');
    });

    t.test('Should remove standard attribute when PATCH uses op: "remove"', async (t) => {
      // User has title from initial creation data
      const { data: initialUser } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.equal(initialUser.title, 'Manager', 'user should have title initially');

      // Remove title using op: "remove"
      const { status, data } = await directorySync.requests.handle(
        requests.removeTitle(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.notOk(data.title, 'title should be removed');
    });

    t.test('Should propagate remove op for standard mapped attributes to user model', async (t) => {
      // Verify user has name fields from initial creation
      const { data: initialUser } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.equal(initialUser.name.givenName, 'Jackson', 'user should have givenName initially');
      t.equal(initialUser.name.familyName, 'M', 'user should have familyName initially');

      // Remove name.givenName and name.familyName using op: "remove"
      const { status, data } = await directorySync.requests.handle(
        requests.removeStandardMappedAttributes(directory, createdUser.id)
      );

      t.equal(status, 200);
      t.notOk(data.name?.givenName, 'givenName should be removed from raw');
      t.notOk(data.name?.familyName, 'familyName should be removed from raw');

      // Verify the user model fields are cleared via the internal user record
      const user = await directorySync.users.get(createdUser.id);
      t.equal(user.data?.first_name, '', 'first_name should be cleared on user model');
      t.equal(user.data?.last_name, '', 'last_name should be cleared on user model');
    });

    t.test('Entra: should set and clear extension attributes via no-path object format', async (t) => {
      // Set extension attributes (Entra no-path format with nested schema object)
      const { status: setStatus, data: setData } = await directorySync.requests.handle(
        requests.entraSetExtensionAttribute(directory, createdUser.id)
      );

      t.equal(setStatus, 200);
      const extKey = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
      t.ok(setData[extKey], 'extension schema key should exist in raw');
      t.equal(setData[extKey].department, 'Engineering', 'department should be set');
      t.equal(setData[extKey].costCenter, 'CC-1234', 'costCenter should be set');

      // Verify it persists
      const { data: fetched } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.equal(fetched[extKey].department, 'Engineering', 'department should persist after re-fetch');

      // Now clear via the same format with empty strings
      const { status: clearStatus, data: clearData } = await directorySync.requests.handle(
        requests.entraClearExtensionAttribute(directory, createdUser.id)
      );

      t.equal(clearStatus, 200);
      t.equal(clearData[extKey].department, '', 'department should be cleared');
      t.equal(clearData[extKey].costCenter, '', 'costCenter should be cleared');

      // Verify clearing persists
      const { data: fetchedAfterClear } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.equal(fetchedAfterClear[extKey].department, '', 'department should still be cleared after re-fetch');
    });

    t.test('Entra: should set and clear extension attribute via path-based format', async (t) => {
      const extKey = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

      // Set via path format (path = "urn:...:User:department", value = "Sales")
      const { status: setStatus, data: setData } = await directorySync.requests.handle(
        requests.entraSetExtensionViaPath(directory, createdUser.id, 'Sales')
      );

      t.equal(setStatus, 200);
      // Path-based format splits "urn:...:User:department" into schema URN + attribute
      t.equal(setData[extKey].department, 'Sales', 'extension attribute should be set via path');

      // Clear via path format with empty string
      const { status: clearStatus, data: clearData } = await directorySync.requests.handle(
        requests.entraSetExtensionViaPath(directory, createdUser.id, '')
      );

      t.equal(clearStatus, 200);
      t.equal(clearData[extKey].department, '', 'extension attribute should be cleared via path');
    });

    t.test('Entra: should clear multi-valued attribute by replacing with empty array', async (t) => {
      // First set phone numbers
      await directorySync.requests.handle(requests.entraPhoneAndAddress(directory, createdUser.id));

      // Verify they're set
      const { data: withPhones } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.ok(Array.isArray(withPhones.phoneNumbers), 'phoneNumbers should be set');
      t.ok(withPhones.phoneNumbers.length > 0, 'phoneNumbers should have entries');

      // Clear by replacing with empty array
      const { status, data } = await directorySync.requests.handle(
        requests.entraClearMultiValuedAttribute(directory, createdUser.id)
      );

      t.equal(status, 200);
      t.ok(Array.isArray(data.phoneNumbers), 'phoneNumbers should still be an array');
      t.equal(data.phoneNumbers.length, 0, 'phoneNumbers should be empty after clear');
    });

    t.test('Entra: should clear filter-path attributes by setting value to empty string', async (t) => {
      // First set phone numbers and addresses via filter paths
      await directorySync.requests.handle(requests.entraPhoneAndAddress(directory, createdUser.id));

      // Verify they're set
      const { data: withData } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      const workPhone = withData.phoneNumbers.find((p: any) => p.type === 'work');
      t.equal(workPhone.value, '555-0100', 'work phone should be set');
      const workAddr = withData.addresses.find((a: any) => a.type === 'work');
      t.equal(workAddr.streetAddress, '100 Enterprise Blvd', 'work address should be set');

      // Clear via filter-path with empty string values
      const { status, data } = await directorySync.requests.handle(
        requests.entraClearFilterPathAttributes(directory, createdUser.id)
      );

      t.equal(status, 200);

      const clearedPhone = data.phoneNumbers.find((p: any) => p.type === 'work');
      t.equal(clearedPhone.value, '', 'work phone value should be cleared to empty string');

      const clearedAddr = data.addresses.find((a: any) => a.type === 'work');
      t.equal(clearedAddr.streetAddress, '', 'work address streetAddress should be cleared to empty string');
    });

    t.test('Should clear custom attributes when PATCH sets them to empty string', async (t) => {
      // First, set some custom attributes
      const { status: setStatus, data: setData } = await directorySync.requests.handle(
        requests.customAttributes(directory, createdUser.id)
      );

      t.equal(setStatus, 200);
      t.equal(setData.companyName, 'Ory');
      t.equal(setData.address.streetAddress, '123 Main St');

      // Now clear them by setting to empty string
      const { status, data } = await directorySync.requests.handle(
        requests.clearCustomAttributes(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.equal(data.companyName, '', 'companyName should be cleared to empty string');
      t.equal(data.address.streetAddress, '', 'address.streetAddress should be cleared to empty string');
    });

    t.test('Should clear attributes when PATCH uses object value with empty strings', async (t) => {
      // Verify the user has title and displayName set from initial creation
      const { data: initialUser } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.ok(initialUser.title || initialUser.displayName, 'user should have title or displayName initially');

      // Clear them via object-style PATCH
      const { status, data } = await directorySync.requests.handle(
        requests.clearCustomAttributesViaObject(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);
      t.equal(data.title, '', 'title should be cleared to empty string');
      t.equal(data.displayName, '', 'displayName should be cleared to empty string');
    });

    t.test('Should clear custom field when PUT omits it', async (t) => {
      // First set a custom attribute via PATCH
      await directorySync.requests.handle(requests.customAttributes(directory, createdUser.id));

      // Verify it's set
      const { data: withCustom } = await directorySync.requests.handle(
        requests.getById(directory, createdUser.id)
      );
      t.equal(withCustom.companyName, 'Ory', 'custom field should be set before PUT');

      // Now PUT the full user without the custom field (simulating Entra removing it)
      const userWithoutCustomField = { ...users[0] };
      const { status, data } = await directorySync.requests.handle(
        requests.updateByIdWithoutCustomField(directory, createdUser.id, userWithoutCustomField)
      );

      t.ok(data);
      t.equal(status, 200);
      t.notOk(data.companyName, 'companyName should not be present after PUT without it');
    });

    t.test('Should be able to update phone numbers and addresses with SCIM filter paths', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.entraPhoneAndAddress(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);

      // Phone numbers should be stored as an array with correct structure
      t.ok(Array.isArray(data.phoneNumbers), 'phoneNumbers should be an array');
      const workPhone = data.phoneNumbers.find((p: any) => p.type === 'work');
      t.ok(workPhone, 'should have a work phone number');
      t.equal(workPhone.value, '555-0100');
      const mobilePhone = data.phoneNumbers.find((p: any) => p.type === 'mobile');
      t.ok(mobilePhone, 'should have a mobile phone number');
      t.equal(mobilePhone.value, '555-0101');

      // Addresses should be stored as an array with correct structure
      t.ok(Array.isArray(data.addresses), 'addresses should be an array');
      const workAddress = data.addresses.find((a: any) => a.type === 'work');
      t.ok(workAddress, 'should have a work address');
      t.equal(workAddress.streetAddress, '100 Enterprise Blvd');
      t.equal(workAddress.locality, 'San Francisco');
      t.equal(workAddress.postalCode, '94105');
      t.equal(workAddress.country, 'US');
    });

    t.test(
      'Entra: should remove specific value from extension multi-valued attribute via URN filter path',
      async (t) => {
        const extKey = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

        // First, set a multi-valued extension attribute with two roles
        const { status: setStatus, data: setData } = await directorySync.requests.handle(
          requests.entraSetExtensionMultiValued(directory, createdUser.id)
        );

        t.equal(setStatus, 200);
        t.ok(setData[extKey], 'extension schema key should exist');
        t.equal(setData[extKey].roles.length, 2, 'should have two roles');

        // Remove only the admin role using URN + filter path
        const { status, data } = await directorySync.requests.handle(
          requests.entraRemoveExtensionFilterPath(directory, createdUser.id)
        );

        t.equal(status, 200);
        t.ok(data[extKey], 'extension schema key should still exist');
        t.equal(data[extKey].roles.length, 1, 'should have one role remaining');
        t.equal(data[extKey].roles[0].value, 'user-role-id', 'only the user role should remain');

        // Verify removal persists
        const { data: fetched } = await directorySync.requests.handle(
          requests.getById(directory, createdUser.id)
        );
        t.equal(fetched[extKey].roles.length, 1, 'removal should persist after re-fetch');
        t.equal(fetched[extKey].roles[0].value, 'user-role-id', 'correct role should persist');
      }
    );

    t.test('Should handle SCIM filter paths for arbitrary attribute names', async (t) => {
      const { status, data } = await directorySync.requests.handle(
        requests.arbitraryFilterPaths(directory, createdUser.id)
      );

      t.ok(data);
      t.equal(status, 200);

      // ims should be stored as an array with correct structure
      t.ok(Array.isArray(data.ims), 'ims should be an array');
      const xmppIm = data.ims.find((im: any) => im.type === 'xmpp');
      t.ok(xmppIm, 'should have an xmpp IM');
      t.equal(xmppIm.value, 'test@test.org');

      // photos should be stored as an array with correct structure
      t.ok(Array.isArray(data.photos), 'photos should be an array');
      const thumbnail = data.photos.find((p: any) => p.type === 'thumbnail');
      t.ok(thumbnail, 'should have a thumbnail photo');
      t.equal(thumbnail.value, 'https://example.com/photo.jpg');
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

  t.test('userName-based dedup contract /', async (t) => {
    t.afterEach(async () => {
      directorySync.users.setTenantAndProduct(directory.tenant, directory.product);
      await directorySync.users.deleteAll(directory.id);
    });

    t.test('POST duplicate userName should return 409 with scimType=uniqueness', async (t) => {
      await directorySync.requests.handle(requests.create(directory, users[0]));

      const { status, data } = await directorySync.requests.handle(requests.create(directory, users[0]));

      t.equal(status, 409);
      t.equal(data.scimType, 'uniqueness');
      t.equal(data.detail, 'User already exists');
    });

    t.test('POST same userName different email should return 409', async (t) => {
      await directorySync.requests.handle(requests.create(directory, users[0]));

      const { status } = await directorySync.requests.handle(
        requests.create(directory, {
          ...users[0],
          emails: [{ primary: true, value: 'different@example.com', type: 'work' }],
        })
      );

      t.equal(status, 409);
    });

    t.test('POST different userName same email should return 201 (LEV-956)', async (t) => {
      await directorySync.requests.handle(requests.create(directory, users[0]));

      const { status } = await directorySync.requests.handle(
        requests.create(directory, {
          ...users[0],
          userName: 'different-user@boxyhq.com',
        })
      );

      t.equal(status, 201);
    });

    t.test('POST case-insensitive userName match should return 409', async (t) => {
      await directorySync.requests.handle(requests.create(directory, users[0]));

      const { status } = await directorySync.requests.handle(
        requests.create(directory, {
          ...users[0],
          userName: users[0].userName.toUpperCase(),
        })
      );

      t.equal(status, 409);
    });

    t.test('PUT rename then POST with old userName should return 201', async (t) => {
      const { data: created } = await directorySync.requests.handle(requests.create(directory, users[0]));

      await directorySync.requests.handle(
        requests.updateById(directory, created.id, {
          ...users[0],
          userName: 'renamed@boxyhq.com',
        })
      );

      const { status } = await directorySync.requests.handle(
        requests.create(directory, {
          ...users[2],
          userName: users[0].userName,
        })
      );

      t.equal(status, 201);
    });

    t.test('POST without userName should return 400', async (t) => {
      const { userName, ...userWithoutUserName } = users[0];

      const { status, data } = await directorySync.requests.handle(
        requests.create(directory, userWithoutUserName)
      );

      t.equal(status, 400);
      t.equal(data.detail, 'userName is required');
    });
  });
});
