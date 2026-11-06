import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST' && req.method !== 'GET') {
    throw { message: 'Method not allowed', statusCode: 405 };
  }

  let body = req.body;
  if (req.method === 'GET') {
    body = req.query;
  }

  const { SAMLResponse, RelayState } = body;

  try {
    const { logoutController } = await jackson();

    const { redirectUrl } = await logoutController.handleResponse({
      SAMLResponse,
      RelayState,
    });

    res.redirect(302, redirectUrl);
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    res.status(statusCode).send(message);
  }
}
