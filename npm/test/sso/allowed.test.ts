import * as allowed from '../../src/controller/oauth/allowed';
import tap from 'tap';

tap.teardown(async () => {
  process.exit(0);
});

tap.test('allowed.ts', async (t) => {
  t.test('redirect without exact match', async (t) => {
    const redirectUrl = 'https://example.com/callback';
    const redirectUrls = ['https://example.com'];

    const result = allowed.redirect(redirectUrl, redirectUrls, false);
    t.equal(result, true);
  });

  t.test('redirect without exact match - failure', async (t) => {
    const redirectUrl = 'https://example.com/callback';
    const redirectUrls = ['https://other.com'];

    const result = allowed.redirect(redirectUrl, redirectUrls, false);
    t.equal(result, false);
  });

  t.test('redirect with exact match', async (t) => {
    const redirectUrl = 'https://example.com/callback';
    const redirectUrls = ['https://example.com/callback'];

    const result = allowed.redirect(redirectUrl, redirectUrls, true);
    t.equal(result, true);
  });

  t.test('redirect with exact match - failure', async (t) => {
    const redirectUrl = 'https://example.com/callback';
    const redirectUrls = ['https://example.com/other'];

    const result = allowed.redirect(redirectUrl, redirectUrls, true);
    t.equal(result, false);
  });
});
