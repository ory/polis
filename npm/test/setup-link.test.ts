import tap from 'tap';
import { jacksonOptions } from './utils';
import { ISetupLinkController } from '../src';

let setupLinkController: ISetupLinkController;
const product = 'jackson';

tap.before(async () => {
  const jackson = await (await import('../src/index')).default(jacksonOptions);
  setupLinkController = jackson.setupLinkController;
});

tap.teardown(async () => {
  process.exit(0);
});

const expireInDays = (timestamp: number) => {
  const diffInMilliseconds = timestamp - new Date().getTime();
  const expireInDays = Math.ceil(diffInMilliseconds / (1000 * 3600 * 24));
  return expireInDays;
};

tap.test('Setup link controller', async (t) => {
  t.test('Create a new setup link', async (t) => {
    const setupLink = await setupLinkController.create({
      tenant: 'tenant-1',
      product,
      service: 'dsync',
    });

    t.ok(setupLink);
    t.match(expireInDays(setupLink.validTill), 3);
  });

  // With custom expiry
  t.test('Create a new setup link with custom expiry', async (t) => {
    const setupLink = await setupLinkController.create({
      tenant: 'tenant-2',
      product,
      service: 'dsync',
      expiryDays: 5,
    });

    t.ok(setupLink);
    t.match(expireInDays(setupLink.validTill), 5);
  });

  // With global expiry
  t.test('Create a new setup link with global expiry', async (t) => {
    const jackson = await (
      await import('../src/index')
    ).default({
      ...jacksonOptions,
      setupLinkExpiryDays: 10,
    });

    setupLinkController = jackson.setupLinkController;

    const setupLink = await setupLinkController.create({
      tenant: 'tenant-3',
      product,
      service: 'dsync',
    });

    t.ok(setupLink);
    t.match(expireInDays(setupLink.validTill), 10);
  });

  t.test('Create a new setup link for sso service', async (t) => {
    const setupLink = await setupLinkController.create({
      name: 'sso for acme',
      tenant: 'acme',
      product,
      service: 'sso',
      description: 'sso setup link for acme',
      defaultRedirectUrl: 'https://acme.com',
      redirectUrl: JSON.stringify(['https://acme.com', 'https://acme.com/login']),
    });

    t.ok(setupLink);
    t.match(setupLink.redirectUrl, ['https://acme.com', 'https://acme.com/login']);
    t.match(setupLink.defaultRedirectUrl, 'https://acme.com');
  });

  t.test('Create a new setup link for dsync service', async (t) => {
    const setupLink = await setupLinkController.create({
      name: 'dsync for acme',
      tenant: 'acme',
      product,
      service: 'dsync',
      webhook_url: 'https://acme.com/webhook',
      webhook_secret: 'webhook-secret',
    });

    t.ok(setupLink);
    t.match(setupLink.webhook_url, 'https://acme.com/webhook');
    t.match(setupLink.webhook_secret, 'webhook-secret');
  });
});
