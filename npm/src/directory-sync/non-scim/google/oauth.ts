import { OAuth2Client, Credentials } from 'google-auth-library';

import { JacksonError, apiError } from '../../../controller/error';
import type { Directory, IDirectoryConfig, JacksonOption, Response } from '../../../typings';

const scope = [
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
  'https://www.googleapis.com/auth/admin.directory.group.readonly',
  'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
];

interface GoogleAuthParams {
  opts: JacksonOption;
  directories: IDirectoryConfig;
}

export class GoogleAuth {
  private opts: JacksonOption;
  private directories: IDirectoryConfig;

  constructor({ directories, opts }: GoogleAuthParams) {
    this.opts = opts;
    this.directories = directories;
  }

  createOAuth2Client(directory: Directory) {
    const googleProvider = this.opts.dsync?.providers?.google;

    const authClient = new OAuth2Client(
      googleProvider?.clientId,
      googleProvider?.clientSecret,
      `${this.opts.externalUrl}${googleProvider?.callbackPath}`
    );

    authClient.setCredentials({
      access_token: directory.google_access_token,
      refresh_token: directory.google_refresh_token,
    });

    return authClient;
  }

  // Generate the Google authorization URL
  async generateAuthorizationUrl(params: {
    directoryId: string;
  }): Promise<Response<{ authorizationUrl: string }>> {
    const { directoryId } = params;

    try {
      const { data: directory, error } = await this.directories.get(directoryId);

      if (error) {
        throw error;
      }

      if (directory?.type !== 'google') {
        throw new JacksonError('Directory is not a Google Directory', 400);
      }

      const oauth2Client = this.createOAuth2Client(directory);

      const authorizationUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        prompt: 'consent',
        scope,
        state: JSON.stringify({ directoryId }),
      });

      const data = {
        authorizationUrl,
      };

      return { data, error: null };
    } catch (err: any) {
      return apiError(err);
    }
  }

  // Get the Google API access token from the authorization code
  async getAccessToken(params: { directoryId: string; code: string }): Promise<Response<Credentials>> {
    const { directoryId, code } = params;

    try {
      const { data: directory, error } = await this.directories.get(directoryId);

      if (error) {
        throw error;
      }

      const oauth2Client = this.createOAuth2Client(directory);

      const { tokens } = await oauth2Client.getToken(code);

      return { data: tokens, error: null };
    } catch (err: any) {
      return apiError(err);
    }
  }

  // Set the Google API access token and refresh token for the directory
  async setToken(params: {
    directoryId: string;
    accessToken: Credentials['access_token'];
    refreshToken: Credentials['refresh_token'];
  }): Promise<Response<Directory>> {
    const { directoryId, accessToken, refreshToken } = params;

    try {
      if (!accessToken) {
        throw new JacksonError(`Access token is required`, 400);
      }

      if (!refreshToken) {
        throw new JacksonError(`Refresh token is required`, 400);
      }

      const { data } = await this.directories.update(directoryId, {
        google_access_token: accessToken,
        google_refresh_token: refreshToken,
      });

      if (!data) {
        throw new JacksonError('Failed to update directory', 400);
      }

      return { data, error: null };
    } catch (err: any) {
      return apiError(err);
    }
  }
}
