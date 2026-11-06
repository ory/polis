import { IDirectorySyncController, DirectoryType, Directory } from '../../src/typings';
import tap from 'tap';
import { jacksonOptions } from '../utils';
import { isConnectionActive } from '../../src/controller/utils';

let directorySync: IDirectorySyncController;

export const directoryPayload = {
  tenant: 'boxyhq',
  product: 'saml-jackson',
  name: 'Directory 1',
  type: 'okta-scim-v2' as DirectoryType,
  webhook_url: 'https://example.com',
  webhook_secret: 'secret',
};

const { tenant, product } = directoryPayload;

tap.before(async () => {
  const { directorySyncController } = await (await import('../../src/index')).default(jacksonOptions);

  directorySync = directorySyncController;
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('directories.', async (t) => {
  t.afterEach(async () => {
    const { data: directoriesFetched } = await directorySync.directories.getByTenantAndProduct(
      tenant,
      product
    );

    if (!directoriesFetched) {
      return;
    }

    // Delete all directories
    for (const directory of directoriesFetched) {
      await directorySync.directories.delete(directory.id);
    }
  });

  t.test('create()', async (t) => {
    t.test('create a directory with all required params', async () => {
      const { data: directory } = await directorySync.directories.create(directoryPayload);

      tap.ok(directory);
      tap.strictSame(directory?.tenant, tenant);
      tap.strictSame(directory?.product, product);
      tap.strictSame(directory?.name, directoryPayload.name);
      tap.strictSame(directory?.type, directoryPayload.type);
      tap.strictSame(directory?.webhook.endpoint, directoryPayload.webhook_url);
      tap.strictSame(directory?.webhook.secret, directoryPayload.webhook_secret);
      tap.strictSame(directory?.log_webhook_events, false);
    });

    t.test('generate a name using tenant and product if name is not provided', async () => {
      const { data: directory } = await directorySync.directories.create({
        ...directoryPayload,
        name: undefined,
      });

      tap.ok(directory);
      tap.strictSame(directory?.name, `scim-${tenant}-${product}`);
    });

    t.test('use generic-scim-v2 type if type is not provided', async () => {
      const { data: directory } = await directorySync.directories.create({
        ...directoryPayload,
        type: undefined,
      });

      tap.ok(directory);
      tap.strictSame(directory?.type, 'generic-scim-v2');
    });

    t.test('should not be able to create a directory without tenant or product', async () => {
      const { data: directory, error } = await directorySync.directories.create({
        ...directoryPayload,
        tenant: '',
        product: '',
      });

      tap.notOk(directory);
      tap.ok(error);
      tap.strictSame(error?.code, 400);
      tap.strictSame(error?.message, 'Missing required parameters.');
    });

    t.test('should not be able to create a directory with invalid type', async () => {
      const { data: directory, error } = await directorySync.directories.create({
        ...directoryPayload,
        type: 'invalid-type' as DirectoryType,
      });

      tap.notOk(directory);
      tap.ok(error);
      tap.strictSame(error?.code, 400);
      tap.strictSame(error?.message, 'Invalid directory type.');
    });

    t.test('create multiple directories for same tenant and product', async () => {
      const { data: directory1 } = await directorySync.directories.create({
        ...directoryPayload,
        name: 'Directory 1',
      });

      const { data: directory2 } = await directorySync.directories.create({
        ...directoryPayload,
        name: 'Directory 2',
      });

      tap.ok(directory1);
      tap.ok(directory2);
      tap.strictSame(directory1?.tenant, tenant);
      tap.strictSame(directory1?.product, product);
      tap.strictSame(directory2?.tenant, tenant);
      tap.strictSame(directory2?.product, product);

      // Fetch the directories
      const { data: directoriesFetched } = await directorySync.directories.getByTenantAndProduct(
        tenant,
        product
      );

      tap.ok(directoriesFetched);
      tap.strictSame(directoriesFetched?.length, 2);
    });
  });

  t.test('get()', async (t) => {
    let directory: Directory;

    t.before(async () => {
      const { data } = await directorySync.directories.create(directoryPayload);

      if (!data) {
        t.fail("Couldn't create a directory");
        return;
      }

      directory = data;
    });

    t.test('get a directory by ID', async (t) => {
      const { data: directoryFetched } = await directorySync.directories.get(directory.id);

      t.ok(directoryFetched);
      t.strictSame(directoryFetched, directory);
      t.match(directoryFetched?.id, directory.id);
    });

    t.test('should not be able to get a directory that does not exist', async (t) => {
      const { data: directoryFetched, error } = await directorySync.directories.get('invalid-id');

      t.notOk(directoryFetched);
      t.ok(error);
      t.strictSame(error?.code, 404);
      t.strictSame(error?.message, 'Directory configuration not found.');
    });

    t.test('should not be able to get a directory without an id', async (t) => {
      const { data: directoryFetched, error } = await directorySync.directories.get('');

      t.notOk(directoryFetched);
      t.ok(error);
      t.strictSame(error?.code, 400);
      t.strictSame(error?.message, 'Missing required parameters.');
    });
  });

  t.test('getByTenantAndProduct()', async (t) => {
    let directory: Directory;

    t.before(async () => {
      const { data } = await directorySync.directories.create(directoryPayload);

      if (!data) {
        t.fail("Couldn't create a directory");
        return;
      }

      directory = data;
    });

    t.test('get a directory by tenant and product', async (t) => {
      const { data: directoriesFetched } = await directorySync.directories.getByTenantAndProduct(
        tenant,
        product
      );

      t.ok(directoriesFetched);
      t.strictSame(directoriesFetched, [directory]);
      t.match(directoriesFetched?.length, 1);
    });

    t.test('should not be able to get a directory that does not exist', async (t) => {
      const { data: directoriesFetched, error } = await directorySync.directories.getByTenantAndProduct(
        'invalid-tenant',
        'invalid-product'
      );

      t.ok(directoriesFetched);
      t.notOk(error);
      t.strictSame(directoriesFetched?.length, 0);
    });
  });

  t.test('update()', async (t) => {
    let directory: Directory;

    t.beforeEach(async () => {
      const { data } = await directorySync.directories.create(directoryPayload);

      if (!data) {
        t.fail("Couldn't create a directory");
        return;
      }

      directory = data;
    });

    t.test('should be able to update a directory', async (t) => {
      const toUpdate = {
        name: 'Directory Updated',
        webhook: {
          endpoint: 'https://my-cool-app.com/webhook',
          secret: 'secret',
        },
        log_webhook_events: true,
      };

      const { data: updatedDirectory } = await directorySync.directories.update(directory.id, {
        ...toUpdate,
      });

      t.ok(updatedDirectory);
      t.same(directory.id, updatedDirectory?.id);
      t.same(updatedDirectory?.name, toUpdate.name);
      t.same(updatedDirectory?.log_webhook_events, toUpdate.log_webhook_events);
      t.match(updatedDirectory?.webhook.endpoint, toUpdate.webhook?.endpoint);
      t.match(updatedDirectory?.webhook.secret, toUpdate.webhook?.secret);

      // Check that the directory was updated
      const { data: directoryFetched } = await directorySync.directories.get(directory.id);

      t.ok(directoryFetched);
      t.same(directoryFetched?.id, updatedDirectory?.id);
      t.same(directoryFetched?.name, toUpdate.name);
      t.same(directoryFetched?.log_webhook_events, toUpdate.log_webhook_events);
      t.match(directoryFetched?.webhook.endpoint, toUpdate.webhook?.endpoint);
      t.match(directoryFetched?.webhook.secret, toUpdate.webhook?.secret);
    });

    t.test('must provide a directory id', async (t) => {
      const { error } = await directorySync.directories.update('', {
        name: 'Directory Updated',
      });

      t.ok(error);
      t.same(error?.code, 400);
      t.same(error?.message, 'Missing required parameters.');
    });
  });

  t.test('delete()', async (t) => {
    let directory: Directory;

    t.beforeEach(async () => {
      const { data } = await directorySync.directories.create(directoryPayload);

      if (!data) {
        t.fail("Couldn't create a directory");
        return;
      }

      directory = data;
    });

    t.test('should be able to delete a directory by ID', async (t) => {
      await directorySync.directories.delete(directory.id);

      const { data: directoryFetched } = await directorySync.directories.get(directory.id);

      t.notOk(directoryFetched);
    });
  });

  t.test('getAll()', async (t) => {
    // Create 2 directories
    await directorySync.directories.create(directoryPayload);
    await directorySync.directories.create({ ...directoryPayload, name: 'Directory 2' });

    const { data: directories } = await directorySync.directories.getAll();

    t.ok(directories);
    t.match(directories?.length, 2);
  });

  t.test('Activate and deactivate the connection', async (t) => {
    const { data: directory } = await directorySync.directories.create(directoryPayload);

    if (!directory) {
      t.fail("Couldn't create a directory");
      return;
    }

    // Deactivate the connection
    await directorySync.directories.update(directory.id, {
      deactivated: true,
    });

    // Get the connection
    const { data: directoryFetched } = await directorySync.directories.get(directory.id);

    t.match(directoryFetched?.deactivated, true);
    t.match(isConnectionActive(directoryFetched!), false);

    // Activate the connection
    await directorySync.directories.update(directory.id, {
      deactivated: false,
    });

    // Get the connection
    const { data: directoryFetched2 } = await directorySync.directories.get(directory.id);

    t.match(directoryFetched2?.deactivated, false);
    t.match(isConnectionActive(directoryFetched2!), true);
  });

  t.test('Fetch the non-scim directories by directory provider', async (t) => {
    // Create a google directory
    const { data: firstDirectory } = await directorySync.directories.create({
      ...directoryPayload,
      name: 'Google Directory 1',
      type: 'google' as DirectoryType,
    });

    // Create an Okta directory
    await directorySync.directories.create({
      ...directoryPayload,
      name: 'Okta Directory 1',
      type: 'okta-scim-v2' as DirectoryType,
    });

    // Create another Google directory
    const { data: secondDirectory } = await directorySync.directories.create({
      ...directoryPayload,
      name: 'Google Directory 2',
      type: 'google' as DirectoryType,
    });

    // Fetch all the directories of type google
    const { data: googleDirectoryFetched } = await directorySync.directories.filterBy({
      provider: 'google',
    });

    t.ok(googleDirectoryFetched);
    t.match(googleDirectoryFetched?.length, 2);
    t.match(googleDirectoryFetched?.[1].id, firstDirectory?.id);
    t.match(googleDirectoryFetched?.[0].id, secondDirectory?.id);
  });

  t.test('The SCIM endpoint should be empty for non-scim provider', async (t) => {
    const { data: directoryCreated } = await directorySync.directories.create({
      ...directoryPayload,
      tenant: 'acme',
      type: 'google' as DirectoryType,
    });

    t.ok(directoryCreated);
    t.match(directoryCreated?.scim.path, '');
    t.match(directoryCreated?.scim.secret, '');
  });

  t.test('Should be able to update the Google credentials', async (t) => {
    const { data: directory } = await directorySync.directories.create({
      ...directoryPayload,
      tenant: 'acme',
      type: 'google' as DirectoryType,
    });

    if (!directory) {
      t.fail("Couldn't create a directory");
      return;
    }

    const { data: directoryUpdated } = await directorySync.directories.update(directory.id, {
      google_access_token: 'access_token',
      google_refresh_token: 'refresh_token',
    });

    t.ok(directoryUpdated);
    t.match(directoryUpdated?.google_access_token, 'access_token');
    t.match(directoryUpdated?.google_refresh_token, 'refresh_token');

    // Check that the directory was updated
    const { data: directoryFetched } = await directorySync.directories.get(directory.id);

    t.ok(directoryFetched);
    t.match(directoryFetched?.google_access_token, 'access_token');
    t.match(directoryFetched?.google_refresh_token, 'refresh_token');
  });

  t.test('Fetch all connections for a product', async (t) => {
    await directorySync.directories.create({
      ...directoryPayload,
      tenant: 'first-tenant',
      product: 'a-new-product',
    });

    const { data: directories, error } = await directorySync.directories.filterBy({
      product: 'a-new-product',
    });

    if (error) {
      t.fail(error.message);
      return;
    }

    t.ok(directories);
    t.match(directories.length, 1);
    t.match(directories[0].tenant, 'first-tenant');
    t.match(directories[0].product, 'a-new-product');
  });
});
