import { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import packageInfo from '../../package.json';
import { logger } from '@lib/logger';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'GET') {
      throw new Error('Method not allowed');
    }
    await jackson();
    res.status(200).json({
      version: packageInfo.version,
    });
  } catch (err: any) {
    logger.error(err, 'HealthCheck failed');
    const { statusCode = 503 } = err;
    res.status(statusCode).json({});
  }
}
