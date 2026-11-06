import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { method } = req;

  if (method !== 'GET') {
    return res
      .setHeader('Allow', 'GET')
      .status(405)
      .json({ error: { message: `Method ${method} Not Allowed` } });
  }

  const { code, state } = req.query as { code: string; state: string };

  try {
    const { directoryId } = JSON.parse(state);

    if (!directoryId) {
      throw new Error('Directory ID not found in state.');
    }

    const { directorySyncController } = await jackson();

    // Fetch the access token and refresh token from the authorization code
    const tokenResponse = await directorySyncController.google.getAccessToken({
      directoryId,
      code,
    });

    if (tokenResponse.error) {
      throw tokenResponse.error;
    }

    // Set the access token and refresh token for the directory
    const response = await directorySyncController.google.setToken({
      directoryId,
      accessToken: tokenResponse.data.access_token,
      refreshToken: tokenResponse.data.refresh_token,
    });

    if (response.error) {
      throw response.error;
    }

    return res.send('Authorized done successfully. You may close this window.');
  } catch (err: any) {
    return res.status(500).send({ err });
  }
};

export default handler;
