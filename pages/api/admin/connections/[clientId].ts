import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { ApiError } from '@lib/error';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
};

// Get connection by clientID
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController } = await jackson();

  const { clientId } = req.query as {
    clientId: string;
  };

  const connections = await connectionAPIController.getConnections({ clientID: clientId });

  if (!connections || connections.length === 0) {
    throw new ApiError('Connection not found', 404);
  }

  res.json(connections);
};

export default handler;
