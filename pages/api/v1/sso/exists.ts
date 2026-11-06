import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';
import type { GetConnectionsQuery } from '@boxyhq/saml-jackson';
import { defaultHandler } from '@lib/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Check if a connection exists
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController } = await jackson();

  const connections = await connectionAPIController.getConnections(req.query as GetConnectionsQuery);

  if (connections.length === 0) {
    return res.status(404).send({});
  } else {
    res.status(204).end();
    return;
  }
};
