import tap from 'tap';
import sinon from 'sinon';
import controllers from '../../src/index';
import { jacksonOptions } from '../utils';
import EventController from '../../src/event';
import type {
  EventPayloadSchema,
  EventType,
  IConnectionAPIController,
  IDirectorySyncController,
  SAMLSSOConnectionWithEncodedMetadata,
  SAMLSSORecord,
} from '../../src/typings';
import { saml_connection } from '../sso/fixture';
import { transformDirectoryConnection, transformSAMLSSOConnection } from '../../src/event/utils';
import { getFakeDirectory } from '../dsync/data/directories';

let ssoConnectionController: IConnectionAPIController;
let directoryConnectionController: IDirectorySyncController['directories'];

tap.before(async () => {
  const jackson = await controllers(jacksonOptions);

  ssoConnectionController = jackson.connectionAPIController;
  directoryConnectionController = jackson.directorySyncController.directories;
});

tap.teardown(async () => {
  process.exit(0);
});

const assertCalledWith = (spy: sinon.SinonSpy, args: any[]) => {
  sinon.assert.calledOnce(spy);
  sinon.assert.calledWith(spy, ...args);

  spy.restore();
};

tap.test('should send sso.created event', async () => {
  const body = {
    ...saml_connection,
    metadataUrl: 'https://mocksaml.com/api/saml/metadata',
  } as SAMLSSOConnectionWithEncodedMetadata;

  const eventType: EventType = 'sso.created';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  const connection = await ssoConnectionController.createSAMLConnection(body);

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformSAMLSSOConnection(connection),
  };

  assertCalledWith(notifySpy, [eventType, connection]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await ssoConnectionController.deleteConnections({
    clientID: connection.clientID,
    clientSecret: connection.clientSecret,
  });
});

tap.test('should send sso.deactivated event', async () => {
  const body = {
    ...saml_connection,
    metadataUrl: 'https://mocksaml.com/api/saml/metadata',
  } as SAMLSSOConnectionWithEncodedMetadata;

  const connection = await ssoConnectionController.createSAMLConnection(body);

  const eventType: EventType = 'sso.deactivated';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  // Deactivate the connection
  await ssoConnectionController.updateSAMLConnection({
    tenant: connection.tenant,
    product: connection.product,
    clientID: connection.clientID,
    clientSecret: connection.clientSecret,
    deactivated: true,
  });

  // Get the connection again to get the updated data
  const connections = await ssoConnectionController.getConnections({
    tenant: connection.tenant,
    product: connection.product,
  });

  const connectionUpdated = connections[0] as SAMLSSORecord;

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformSAMLSSOConnection(connectionUpdated),
  };

  assertCalledWith(notifySpy, [eventType, connectionUpdated]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await ssoConnectionController.deleteConnections({
    clientID: connection.clientID,
    clientSecret: connection.clientSecret,
  });
});

tap.test('should send sso.activated event', async () => {
  const body = {
    ...saml_connection,
    metadataUrl: 'https://mocksaml.com/api/saml/metadata',
  } as SAMLSSOConnectionWithEncodedMetadata;

  const connection = await ssoConnectionController.createSAMLConnection(body);

  const eventType: EventType = 'sso.activated';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  // Aactivate the connection
  await ssoConnectionController.updateSAMLConnection({
    tenant: connection.tenant,
    product: connection.product,
    clientID: connection.clientID,
    clientSecret: connection.clientSecret,
    deactivated: false,
  });

  // Get the connection again to get the updated data
  const connections = await ssoConnectionController.getConnections({
    tenant: connection.tenant,
    product: connection.product,
  });

  const connectionUpdated = connections[0] as SAMLSSORecord;

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformSAMLSSOConnection(connectionUpdated),
  };

  assertCalledWith(notifySpy, [eventType, connectionUpdated]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await ssoConnectionController.deleteConnections({
    clientID: connection.clientID,
    clientSecret: connection.clientSecret,
  });
});

tap.test('should send sso.deleted event', async () => {
  const body = {
    ...saml_connection,
    metadataUrl: 'https://mocksaml.com/api/saml/metadata',
  } as SAMLSSOConnectionWithEncodedMetadata;

  // Create a connection
  await ssoConnectionController.createSAMLConnection(body);

  const eventType: EventType = 'sso.deleted';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  const connections = await ssoConnectionController.getConnections({
    tenant: saml_connection.tenant,
    product: saml_connection.product,
  });

  const connection = connections[0] as SAMLSSORecord;

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: saml_connection.tenant,
    product: saml_connection.product,
    data: transformSAMLSSOConnection(connection),
  };

  // Delete the connection
  await ssoConnectionController.deleteConnections({
    clientID: connection.clientID,
    clientSecret: connection.clientSecret,
  });

  assertCalledWith(notifySpy, [eventType, connection]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);
});

tap.test('should send dsync.created event', async (t) => {
  const eventType: EventType = 'dsync.created';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  // Create a connection
  const { data: connection, error } = await directoryConnectionController.create(getFakeDirectory());

  if (!connection) {
    t.fail('No connection was created');
    throw error;
  }

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformDirectoryConnection(connection),
  };

  assertCalledWith(notifySpy, [eventType, connection]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await directoryConnectionController.delete(connection.id);
});

tap.test('should send dsync.deactivated event', async (t) => {
  // Create a connection
  const { data: connection, error } = await directoryConnectionController.create(getFakeDirectory());

  if (!connection) {
    t.fail('No connection was created');
    throw error;
  }

  const eventType: EventType = 'dsync.deactivated';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  // Deactivate the connection
  const { data: connectionUpdated } = await directoryConnectionController.update(connection.id, {
    deactivated: true,
  });

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformDirectoryConnection(connectionUpdated!),
  };

  assertCalledWith(notifySpy, [eventType, connectionUpdated]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await directoryConnectionController.delete(connection.id);
});

tap.test('should send dsync.activated event', async (t) => {
  // Create a connection
  const { data: connection, error } = await directoryConnectionController.create(getFakeDirectory());

  if (!connection) {
    t.fail('No connection was created');
    throw error;
  }

  const eventType: EventType = 'dsync.activated';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  // Activate the connection
  const { data: connectionUpdated } = await directoryConnectionController.update(connection.id, {
    deactivated: false,
  });

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformDirectoryConnection(connectionUpdated!),
  };

  assertCalledWith(notifySpy, [eventType, connectionUpdated]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await directoryConnectionController.delete(connection.id);
});

tap.test('should send dsync.deleted event', async (t) => {
  // Create a connection
  const { data: connection, error } = await directoryConnectionController.create(getFakeDirectory());

  if (!connection) {
    t.fail('No connection was created');
    throw error;
  }

  const eventType: EventType = 'dsync.deleted';
  const sendWebhookEventSpy = sinon.spy(EventController.prototype, 'sendWebhookEvent');
  const notifySpy = sinon.spy(EventController.prototype, 'notify');

  const payload: EventPayloadSchema = {
    event: eventType,
    tenant: connection.tenant,
    product: connection.product,
    data: transformDirectoryConnection(connection),
  };

  // Delete the connection
  await directoryConnectionController.delete(connection.id);

  assertCalledWith(notifySpy, [eventType, connection]);
  assertCalledWith(sendWebhookEventSpy, [jacksonOptions.webhook, payload]);

  await directoryConnectionController.delete(connection.id);
});
