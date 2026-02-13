import jackson from '@lib/jackson';
import { oidcMetadataParse, strategyChecker } from '@lib/utils';
import { NextApiRequest, NextApiResponse } from 'next';
import type { DelConnectionsQuery } from '@boxyhq/saml-jackson';
import { validateDevelopmentModeLimits } from '@lib/development-mode';
import { defaultHandler } from '@lib/api';
import { normalizeBooleanParam } from '@lib/api/utils';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
    POST: handlePOST,
    PATCH: handlePATCH,
    DELETE: handleDELETE,
  });
}

// Get all connections
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController } = await jackson();

  const params = req.query as any;

  if ('sort' in params) {
    params['sort'] = params.sort === 'true';
  }

  const connections = await connectionAPIController.getConnections(params);

  return res.json(connections);
};

// Create a new connection
const handlePOST = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController } = await jackson();

  const { isSAML, isOIDC } = strategyChecker(req);

  if (!isSAML && !isOIDC) {
    throw { message: 'Missing SSO connection params', statusCode: 400 };
  }

  await validateDevelopmentModeLimits(req.body.product, 'sso');

  // Create SAML connection
  if (isSAML) {
    const connection = await connectionAPIController.createSAMLConnection(req.body);

    return res.json(connection);
  }

  // Create OIDC connection
  if (isOIDC) {
    const connection = await connectionAPIController.createOIDCConnection(oidcMetadataParse(req.body));

    return res.json(connection);
  }
};

// Update a connection
const handlePATCH = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController } = await jackson();

  const { isSAML, isOIDC } = strategyChecker(req);

  if (!isSAML && !isOIDC) {
    throw { message: 'Missing SSO connection params', statusCode: 400 };
  }

  const body = { ...req.body };

  const returnConnection = req.headers['x-polis-return-connection'] === 'true';

  if ('deactivated' in req.body) {
    body.deactivated = normalizeBooleanParam(req.body.deactivated);
  }

  // Update SAML connection
  if (isSAML) {
    if ('forceAuthn' in req.body) {
      body.forceAuthn = normalizeBooleanParam(req.body.forceAuthn);
    }
    const updatedConnection = await connectionAPIController.updateSAMLConnection(body);

    if (returnConnection) {
      return res.json(updatedConnection);
    }

    res.status(204).end();
  }

  // Update OIDC connection
  if (isOIDC) {
    const updatedConnection = await connectionAPIController.updateOIDCConnection(
      oidcMetadataParse(body) as any
    );

    if (returnConnection) {
      return res.json(updatedConnection);
    }

    res.status(204).end();
  }
};

// Delete a connection
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController } = await jackson();

  await connectionAPIController.deleteConnections(req.query as DelConnectionsQuery);

  res.status(204).end();
};
