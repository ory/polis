import { IDirectorySyncController, Directory, DirectorySyncEvent } from '../../src/typings';
import tap from 'tap';
import groups from './data/groups';
import users from './data/users';
import { default as usersRequest } from './data/user-requests';
import { default as groupRequest } from './data/group-requests';
import { getFakeDirectory } from './data/directories';
import { jacksonOptions } from '../utils';
import sinon from 'sinon';
import * as axiosModule from '../../src/event/axios';
import { createSignatureString } from '../../src/event/webhook';
import { AxiosInstance } from 'axios';

let directorySync: IDirectorySyncController;
let directory: Directory;
const fakeDirectory = getFakeDirectory();

const webhook: Directory['webhook'] = {
  endpoint: 'http://localhost',
  secret: 'secret',
};

tap.before(async () => {
  const jackson = await (await import('../../src/index')).default(jacksonOptions);

  directorySync = jackson.directorySyncController;

  // Create a directory before starting the test
  const { data, error } = await directorySync.directories.create({
    ...fakeDirectory,
    webhook_url: webhook.endpoint,
    webhook_secret: webhook.secret,
  });

  if (error || !data) {
    tap.fail("Couldn't create a directory");
    return;
  }

  directory = data;

  // Turn on webhook event logging for the directory
  await directorySync.directories.update(directory.id, {
    log_webhook_events: true,
  });

  directorySync.webhookLogs.setTenantAndProduct(directory.tenant, directory.product);
  directorySync.users.setTenantAndProduct(directory.tenant, directory.product);
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('Webhook Events /', async (t) => {
  t.teardown(async () => {
    await directorySync.directories.delete(directory.id);
  });

  t.test('Webhook Events / ', async (t) => {
    t.afterEach(async () => {
      await directorySync.webhookLogs.deleteAll(directory.id);
      await directorySync.users.deleteAll(directory.id);
    });

    t.test("Should be able to get the directory's webhook", async (t) => {
      t.match(directory.webhook.endpoint, webhook.endpoint);
      t.match(directory.webhook.secret, webhook.secret);
    });

    t.test('Should not log events if the directory has no webhook', async (t) => {
      await directorySync.directories.update(directory.id, {
        webhook: {
          endpoint: '',
          secret: '',
        },
      });

      // Create a user
      await directorySync.requests.handle(usersRequest.create(directory, users[0]));

      const { data: events } = await directorySync.webhookLogs.getAll();

      t.equal(events.length, 0);

      // Restore the directory's webhook
      await directorySync.directories.update(directory.id, {
        webhook: {
          endpoint: webhook.endpoint,
          secret: webhook.secret,
        },
      });
    });

    t.test('Should not log webhook events if the logging is turned off', async (t) => {
      // Turn off webhook event logging for the directory
      await directorySync.directories.update(directory.id, {
        log_webhook_events: false,
      });

      // Create a user
      await directorySync.requests.handle(usersRequest.create(directory, users[0]));

      const { data: events } = await directorySync.webhookLogs.getAll();

      t.equal(events.length, 0);

      // Turn on webhook event logging for the directory
      await directorySync.directories.update(directory.id, {
        log_webhook_events: true,
      });
    });

    t.test('Should be able to get an event by id', async (t) => {
      // Create a user
      await directorySync.requests.handle(usersRequest.create(directory, users[0]));

      const { data: logs } = await directorySync.webhookLogs.getAll();

      const log = await directorySync.webhookLogs.get(logs[0].id);

      t.equal(log.id, logs[0].id);
    });

    t.test('Should send user related events', async (t) => {
      // Mock the entire module's createAxiosInstance function
      const postSpy = sinon.spy();
      const axiosInstanceStub = {
        post: postSpy,
      } as unknown as AxiosInstance;

      sinon.stub(axiosModule, 'createAxiosInstance').returns(axiosInstanceStub);

      // Create the user
      const { data: createdUser } = await directorySync.requests.handle(
        usersRequest.create(directory, users[0])
      );

      // Update the user
      const { data: updatedUser } = await directorySync.requests.handle(
        usersRequest.updateById(directory, createdUser.id, users[0])
      );

      // Delete the user
      const { data: deletedUser } = await directorySync.requests.handle(
        usersRequest.deleteById(directory, createdUser.id)
      );

      // Verify the post was called three times
      t.equal(postSpy.callCount, 3);
      t.ok(postSpy.calledWith(webhook.endpoint));

      // Restore the stub
      sinon.restore();

      const { data: logs } = await directorySync.webhookLogs.getAll();

      t.ok(logs);
      t.equal(logs.length, 3);

      if (!Array.isArray(logs[0].payload)) {
        t.match(logs[0].payload.event, 'user.deleted');
        t.match(logs[0].payload.directory_id, directory.id);
        t.hasStrict(logs[0].payload.data.raw, deletedUser);
      }

      if (!Array.isArray(logs[1].payload)) {
        t.match(logs[1].payload.event, 'user.updated');
        t.match(logs[1].payload.directory_id, directory.id);
        t.hasStrict(logs[1].payload.data.raw, updatedUser);
      }

      if (!Array.isArray(logs[2].payload)) {
        t.match(logs[2].payload.event, 'user.created');
        t.match(logs[2].payload.directory_id, directory.id);
        t.hasStrict(logs[2].payload.data.raw, createdUser);
      }

      await directorySync.users.deleteAll(directory.id);
    });

    t.test('Should send group related events', async (t) => {
      // Mock the entire module's createAxiosInstance function
      const postSpy = sinon.spy();
      const axiosInstanceStub = {
        post: postSpy,
      } as unknown as AxiosInstance;

      sinon.stub(axiosModule, 'createAxiosInstance').returns(axiosInstanceStub);

      // Create the group
      const { data: createdGroup } = await directorySync.requests.handle(
        groupRequest.create(directory, groups[0])
      );

      // Update the group
      const { data: updatedGroup } = await directorySync.requests.handle(
        groupRequest.updateById(directory, createdGroup.id, groups[0])
      );

      // Delete the group
      const { data: deletedGroup } = await directorySync.requests.handle(
        groupRequest.deleteById(directory, createdGroup.id)
      );

      // Verify the post was called three times
      t.equal(postSpy.callCount, 3);
      t.ok(postSpy.calledWith(webhook.endpoint));

      // Restore the stub
      sinon.restore();

      const { data: logs } = await directorySync.webhookLogs.getAll();

      t.ok(logs);
      t.equal(logs.length, 3);

      if (!Array.isArray(logs[0].payload)) {
        t.match(logs[0].payload.event, 'group.deleted');
        t.match(logs[0].payload.directory_id, directory.id);
        t.hasStrict(logs[0].payload.data.raw, deletedGroup);
      }

      if (!Array.isArray(logs[1].payload)) {
        t.match(logs[1].payload.event, 'group.updated');
        t.match(logs[1].payload.directory_id, directory.id);
        t.hasStrict(logs[1].payload.data.raw, updatedGroup);
      }

      if (!Array.isArray(logs[2].payload)) {
        t.match(logs[2].payload.event, 'group.created');
        t.match(logs[2].payload.directory_id, directory.id);
        t.hasStrict(logs[2].payload.data.raw, createdGroup);
      }
    });
  });

  t.test('Should send group membership related events', async (t) => {
    const postSpy = sinon.spy();
    const axiosInstanceStub = {
      post: postSpy,
    } as unknown as AxiosInstance;

    sinon.stub(axiosModule, 'createAxiosInstance').returns(axiosInstanceStub);

    // Create the user
    const { data: createdUser } = await directorySync.requests.handle(
      usersRequest.create(directory, users[0])
    );

    // Create the group
    const { data: createdGroup } = await directorySync.requests.handle(
      groupRequest.create(directory, groups[0])
    );

    // Add the user to the group
    await directorySync.requests.handle(
      groupRequest.addMembers(directory, createdGroup.id, [{ value: createdUser.id }])
    );

    // Remove the user from the group
    await directorySync.requests.handle(
      groupRequest.removeMembers(
        directory,
        createdGroup.id,
        [{ value: createdUser.id }],
        `members[value eq "${createdUser.id}"]`
      )
    );

    // Verify the post was called three times
    t.equal(postSpy.callCount, 4);
    t.ok(postSpy.calledWith(webhook.endpoint));

    // Restore the stub
    sinon.restore();

    const { data: logs } = await directorySync.webhookLogs.getAll();

    t.ok(logs);
    t.equal(logs.length, 4);

    if (!Array.isArray(logs[0].payload)) {
      t.match(logs[0].payload.event, 'group.user_removed');
      t.match(logs[0].payload.directory_id, directory.id);
      t.hasStrict(logs[0].payload.data.raw, createdUser);
    }

    if (!Array.isArray(logs[1].payload)) {
      t.match(logs[1].payload.event, 'group.user_added');
      t.match(logs[1].payload.directory_id, directory.id);
      t.hasStrict(logs[1].payload.data.raw, createdUser);
    }

    await directorySync.users.delete(createdUser.id);
    await directorySync.groups.delete(createdGroup.id);
  });

  t.test('createSignatureString()', async (t) => {
    const event: DirectorySyncEvent = {
      event: 'user.created',
      directory_id: directory.id,
      tenant: directory.tenant,
      product: directory.product,
      data: {
        raw: [],
        id: 'user-id',
        first_name: 'Kiran',
        last_name: 'Krishnan',
        email: 'kiran@boxyhq.com',
        active: true,
      },
    };

    const signatureString = createSignatureString(directory.webhook.secret, event);
    const parts = signatureString.split(',');

    t.ok(signatureString);
    t.ok(parts[0].match(/^t=[0-9a-f]/));
    t.ok(parts[1].match(/^s=[0-9a-f]/));

    // Empty secret should create an empty signature
    const emptySignatureString = createSignatureString('', event);

    t.match(emptySignatureString, '');
  });
});
