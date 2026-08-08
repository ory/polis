import tap from 'tap';
import { extractOIDCEmail } from '../../src/controller/utils';

tap.test('extractOIDCEmail', async (t) => {
  await t.test('prefers email from id token claims', async (t) => {
    t.equal(
      extractOIDCEmail(
        { email: 'id@example.com', preferred_username: 'user@example.com' },
        { email: 'info@example.com' }
      ),
      'id@example.com'
    );
  });

  await t.test('falls back to userinfo email', async (t) => {
    t.equal(extractOIDCEmail({}, { email: 'info@example.com' }), 'info@example.com');
  });

  await t.test('handles email as an array (Entra multiple emails)', async (t) => {
    t.equal(
      extractOIDCEmail({}, { email: ['first@example.com', 'second@example.com'] }),
      'first@example.com'
    );
  });

  await t.test('id token email array takes precedence over userinfo scalar', async (t) => {
    t.equal(extractOIDCEmail({ email: ['id@example.com'] }, { email: 'info@example.com' }), 'id@example.com');
  });

  await t.test('skips empty array entries', async (t) => {
    t.equal(extractOIDCEmail({}, { email: ['', 'second@example.com'] }), 'second@example.com');
  });

  await t.test('falls back to preferred_username (Entra)', async (t) => {
    t.equal(extractOIDCEmail({ preferred_username: 'user@company.com' }, {}), 'user@company.com');
    t.equal(extractOIDCEmail({}, { preferred_username: 'user@company.com' }), 'user@company.com');
  });

  await t.test('falls back to upn (Entra)', async (t) => {
    t.equal(extractOIDCEmail({ upn: 'user@company.com' }, {}), 'user@company.com');
    t.equal(extractOIDCEmail({}, { upn: 'user@company.com' }), 'user@company.com');
  });

  await t.test('returns undefined when no email-like claim exists', async (t) => {
    t.equal(extractOIDCEmail({ sub: '123' }, { name: 'Test User' }), undefined);
  });
});
