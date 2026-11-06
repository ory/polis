import jackson from '@lib/jackson';
import { logger } from '@lib/logger';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    throw { message: 'Method not allowed', statusCode: 405 };
  }

  const { nameId, tenant, product, redirectUrl } = req.query;

  try {
    const { logoutController } = await jackson();

    const { logoutUrl, logoutForm } = await logoutController.createRequest({
      nameId: <string>nameId,
      tenant: <string>tenant,
      product: <string>product,
      redirectUrl: <string>redirectUrl,
    });

    if (logoutUrl) {
      res.redirect(302, logoutUrl);
    } else {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(logoutForm);
    }
  } catch (err: any) {
    logger.error(err, 'error in creating SAML SLO request');
    const { message, statusCode = 500 } = err;

    res.status(statusCode).send(message);
  }
}
