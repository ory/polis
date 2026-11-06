import { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { setErrorCookieAndRedirect } from '@lib/utils';
import { OIDCAuthzResponsePayload } from '@boxyhq/saml-jackson';
import { logger } from '@lib/logger';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'GET') {
      throw { message: 'Method not allowed', statusCode: 405 };
    }

    const { oauthController } = await jackson();

    const { redirect_url, response_form, error } = await oauthController.oidcAuthzResponse(
      req.query as OIDCAuthzResponsePayload
    );

    if (redirect_url) {
      if (error) {
        logger.error(`Error processing OIDC IdP response: ${error}`);
      }
      res.redirect(302, redirect_url);
    }

    if (response_form) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(response_form);
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;
    logger.error(err, 'Error processing OIDC IdP response');

    setErrorCookieAndRedirect(res, { message, statusCode });
  }
}
