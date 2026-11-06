import { defaultHandler } from '@lib/api';
import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController, directorySyncController, identityFederationController } = await jackson();

  const sso_connections_count = await connectionAPIController.getCount();
  const dsync_connections_count = await directorySyncController.directories.getCount();
  const identity_federation_count = await identityFederationController.app.getCount();

  return res.json({
    data: {
      sso_connections: sso_connections_count,
      dsync_connections: dsync_connections_count,
      identity_federation_apps: identity_federation_count,
    },
  });
};
