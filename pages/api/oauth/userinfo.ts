import { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { extractAuthToken } from '@lib/auth';
import { logger } from '@lib/logger';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'GET') {
      throw { message: 'Method not allowed', statusCode: 405 };
    }

    const { oauthController } = await jackson();
    let token: string | null = extractAuthToken(req);

    // check for query param
    if (!token) {
      let arr: string[] = [];
      arr = arr.concat(req.query.access_token || '');
      if (arr[0].length > 0) {
        token = arr[0];
      }
    }

    if (!token) {
      logger.error('Userinfo error: token not found in request');
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const profile = await oauthController.userInfo(token);

    res.json(profile);
  } catch (err: any) {
    logger.error(err, 'Userinfo error');
    const { message, statusCode = 500 } = err;

    res.status(statusCode).json({ message });
  }
}
