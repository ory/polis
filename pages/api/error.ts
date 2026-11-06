import { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { getErrorMessageFromCookie } from '@lib/utils';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'GET') {
      throw new Error('Method not allowed');
    }
    await jackson();
    const error = getErrorMessageFromCookie(req.cookies.polis_error);
    res.status(error.statusCode || 400).json(error || {});
  } catch (err: any) {
    const { statusCode = 503 } = err;
    res.status(statusCode).json({});
  }
}
