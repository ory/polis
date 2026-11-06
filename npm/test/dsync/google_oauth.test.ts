import tap from 'tap';

import { jacksonOptions } from '../utils';
import { IDirectorySyncController, DirectoryType, Directory } from '../../src/typings';

let directory: Directory;
let directorySyncController: IDirectorySyncController;

const directoryPayload = {
  tenant: 'boxyhq',
  product: 'saml-jackson-google',
  name: 'Google Directory',
  type: 'google' as DirectoryType,
  google_access_token: 'access_token',
  google_refresh_token: 'refresh_token',
};

tap.before(async () => {
  directorySyncController = (await (await import('../../src/index')).default(jacksonOptions))
    .directorySyncController;

  const { data, error } = await directorySyncController.directories.create(directoryPayload);

  if (error) {
    throw error;
  }

  directory = data;
});

tap.teardown(async () => {
  process.exit(0);
});

tap.test('generate the Google API authorization URL', async (t) => {
  const result = await directorySyncController.google.generateAuthorizationUrl({
    directoryId: directory.id,
  });

  t.ok(result);
  t.strictSame(result.error, null);

  const parsedUrl = new URL(result.data?.authorizationUrl || '');

  t.strictSame(parsedUrl.origin, 'https://accounts.google.com');
  t.strictSame(parsedUrl.pathname, '/o/oauth2/v2/auth');
  t.strictSame(
    {
      access_type: parsedUrl.searchParams.get('access_type'),
      prompt: parsedUrl.searchParams.get('prompt'),
      response_type: parsedUrl.searchParams.get('response_type'),
      client_id: parsedUrl.searchParams.get('client_id'),
      redirect_uri: parsedUrl.searchParams.get('redirect_uri'),
      scope: parsedUrl.searchParams.get('scope'),
      state: parsedUrl.searchParams.get('state'),
    },
    {
      access_type: 'offline',
      prompt: 'consent',
      response_type: 'code',
      client_id: 'GOOGLE_CLIENT_ID',
      redirect_uri: `${jacksonOptions.externalUrl}${jacksonOptions.dsync?.providers?.google.callbackPath}`,
      state: JSON.stringify({ directoryId: directory.id }),
      scope:
        'https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly',
    }
  );

  t.end();
});

tap.test('set access token and refresh token', async (t) => {
  const { data: updatedDirectory } = await directorySyncController.google.setToken({
    directoryId: directory.id,
    accessToken: 'ACCESS_TOKEN',
    refreshToken: 'REFRESH_TOKEN',
  });

  t.ok(updatedDirectory);
  t.strictSame(updatedDirectory?.google_access_token, 'ACCESS_TOKEN');
  t.strictSame(updatedDirectory?.google_refresh_token, 'REFRESH_TOKEN');

  const { data: directoryFetched } = await directorySyncController.directories.get(directory.id);

  t.ok(directoryFetched);
  t.strictSame(directoryFetched?.google_access_token, 'ACCESS_TOKEN');
  t.strictSame(directoryFetched?.google_refresh_token, 'REFRESH_TOKEN');

  t.end();
});
