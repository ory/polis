// Maintain /config path for backward compatibility

import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';
import type { GetConfigQuery } from '@boxyhq/saml-jackson';
import { logger } from '@lib/logger';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const { connectionAPIController } = await jackson();
    if (req.method === 'GET') {
      const rsp = await connectionAPIController.getConfig(req.query as GetConfigQuery);
      if (Object.keys(rsp).length === 0) {
        res.status(404).send({});
      } else {
        res.status(204).end();
      }
    } else {
      throw { message: 'Method not allowed', statusCode: 405 };
    }
  } catch (err: any) {
    logger.error(err, 'config api error');
    const { message, statusCode = 500 } = err;

    res.status(statusCode).send(message);
  }
}
