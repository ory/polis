import { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { OIDCIdPInitiatedReq } from '@boxyhq/saml-jackson';
import { setErrorCookieAndRedirect } from '@lib/utils';
import { logger } from '@lib/logger';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'GET' && req.method !== 'POST') {
      throw { message: 'Method not allowed', statusCode: 405 };
    }

    const { identityFederationController } = await jackson();
    let requestParams;
    const { fedAppId } = req.query;

    if (req.method === 'GET') {
      requestParams = req.query;
    } else if (req.method === 'POST') {
      // explicitly added fedAppId here to align with GET which contains fedAppId in req.query
      requestParams = { ...req.body, fedAppId };
    }

    const { redirect_url } = await identityFederationController.idpLogin.oidcInitiateLogin(
      requestParams as unknown as OIDCIdPInitiatedReq & { fedAppId: string }
    );
    if (redirect_url) {
      res.redirect(302, redirect_url);
    }
  } catch (err: any) {
    logger.error(err, 'OIDC IdP initiated login error');
    const { message, statusCode = 500 } = err;

    setErrorCookieAndRedirect(res, { message, statusCode });
  }
}
