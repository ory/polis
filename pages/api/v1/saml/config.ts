// Maintain /config path for backward compatibility

import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';
import type { DelConnectionsQuery, GetConfigQuery } from '@boxyhq/saml-jackson';
import { logger } from '@lib/logger';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const { connectionAPIController } = await jackson();
    if (req.method === 'POST') {
      res.json(await connectionAPIController.config(req.body));
    } else if (req.method === 'GET') {
      res.json(await connectionAPIController.getConfig(req.query as GetConfigQuery));
    } else if (req.method === 'PATCH') {
      res.status(204).end(await connectionAPIController.updateConfig(req.body));
    } else if (req.method === 'DELETE') {
      res.status(204).end(await connectionAPIController.deleteConfig(req.query as DelConnectionsQuery));
    } else {
      throw { message: 'Method not allowed', statusCode: 405 };
    }
  } catch (err: any) {
    logger.error(err, 'config api error');
    const { message, statusCode = 500 } = err;

    res.status(statusCode).send(message);
  }
}
