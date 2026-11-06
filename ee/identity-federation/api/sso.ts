import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { setErrorCookieAndRedirect } from '@lib/utils';
import { logger } from '@lib/logger';

type SAMLRequest = {
  SAMLRequest: string;
  RelayState: string;
  samlBinding?: ProtocolBinding;
  idp_hint?: string;
};

type ProtocolBinding = 'HTTP-POST' | 'HTTP-Redirect';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const { method } = req;

    switch (method) {
      case 'GET':
        await handleSAMLRequest(req, res, 'HTTP-Redirect');
        break;
      case 'POST':
        await handleSAMLRequest(req, res, 'HTTP-POST');
        break;
      default:
        res.setHeader('Allow', 'GET, POST');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    logger.error(err, 'SAML Federation authorize error');
    const { message, statusCode = 500 } = err;

    setErrorCookieAndRedirect(res, { message, statusCode });
  }
}

// Handle the SAML Request from Service Provider
// This endpoint act as Single Sign On (SSO) URL
async function handleSAMLRequest(req: NextApiRequest, res: NextApiResponse, binding: ProtocolBinding) {
  let samlRequest = '';
  let relayState = '';
  let idpHint: string | undefined;
  let samlBinding = binding;

  if (samlBinding === 'HTTP-POST') {
    const { SAMLRequest, RelayState } = req.body as SAMLRequest;

    samlRequest = SAMLRequest;
    relayState = RelayState;
  } else {
    const { SAMLRequest, RelayState, idp_hint } = req.query as SAMLRequest;

    samlRequest = SAMLRequest;
    relayState = RelayState;
    idpHint = idp_hint || undefined;
    samlBinding = (req.query.samlBinding as ProtocolBinding) || samlBinding;
  }

  if (!['HTTP-POST', 'HTTP-Redirect'].includes(samlBinding)) {
    throw new Error('Invalid protocol binding. We support only HTTP-POST and HTTP-Redirect.');
  }

  if (!samlRequest) {
    throw new Error('SAMLRequest is required to proceed.');
  }

  const { identityFederationController } = await jackson();

  const response = await identityFederationController.sso.getAuthorizeUrl({
    request: samlRequest,
    relayState,
    idp_hint: idpHint,
    samlBinding,
  });

  if (!response) {
    throw new Error('Unable to create SAML Federated request. Error creating authorize url.');
  }

  if (response?.redirect_url) {
    res.redirect(302, response.redirect_url);
  }

  if (response?.authorize_form) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(response.authorize_form);
  }
}
