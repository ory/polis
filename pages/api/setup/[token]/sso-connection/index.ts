import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { oidcMetadataParse, strategyChecker } from '@lib/utils';
import { validateDevelopmentModeLimits } from '@lib/development-mode';
import { defaultHandler } from '@lib/api';

const withSetupLink = (
  handler: (req: NextApiRequest, res: NextApiResponse, setupLink: any) => Promise<void>
) => {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const { token } = req.query as { token: string };
    const { setupLinkController } = await jackson();
    const setupLink = await setupLinkController.getByToken(token);
    return handler(req, res, setupLink);
  };
};

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: withSetupLink(handleGET),
    POST: withSetupLink(handlePOST),
    PATCH: withSetupLink(handlePATCH),
    DELETE: withSetupLink(handleDELETE),
  });
};

const handleGET = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { connectionAPIController } = await jackson();

  const connections = await connectionAPIController.getConnections({
    tenant: setupLink.tenant,
    product: setupLink.product,
  });

  const _connections = connections.map((connection) => {
    return {
      clientID: connection.clientID,
      name: connection.name,
      deactivated: connection.deactivated,
      ...('forceAuthn' in connection ? { forceAuthn: connection.forceAuthn } : undefined),
      ...('idpMetadata' in connection
        ? {
            idpMetadata: {
              provider: connection.idpMetadata.provider,
              friendlyProviderName: connection.idpMetadata.friendlyProviderName,
            },
          }
        : undefined),
      ...('oidcProvider' in connection
        ? {
            oidcProvider: {
              provider: connection.oidcProvider.provider,
              friendlyProviderName: connection.oidcProvider.friendlyProviderName,
            },
          }
        : undefined),
    };
  });

  res.json(_connections);
};

const handlePOST = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { connectionAPIController } = await jackson();

  const body = {
    ...req.body,
    ...setupLink,
  };

  await validateDevelopmentModeLimits(body.product, 'sso');

  const { isSAML, isOIDC } = strategyChecker(req);

  if (isSAML) {
    await connectionAPIController.createSAMLConnection(body);
  } else if (isOIDC) {
    await connectionAPIController.createOIDCConnection(oidcMetadataParse(body));
  } else {
    throw { message: 'Missing SSO connection params', statusCode: 400 };
  }

  res.status(201).json({ data: null });
};

const handleDELETE = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { connectionAPIController } = await jackson();

  const { clientID, clientSecret } = req.query as { clientID: string; clientSecret: string };

  const connections = await connectionAPIController.getConnections({
    clientID,
  });

  const { tenant, product } = connections[0];

  if (tenant !== setupLink.tenant || product !== setupLink.product) {
    throw { message: 'Tenant/Product mismatch', statusCode: 400 };
  }

  await connectionAPIController.deleteConnections({ clientID, clientSecret });

  res.json({ data: null });
};

const handlePATCH = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { connectionAPIController } = await jackson();

  const {
    deactivated,
    clientID,
    metadataUrl,
    encodedRawMetadata,
    forceAuthn,
    oidcClientId,
    oidcClientSecret,
    oidcDiscoveryUrl,
    oidcMetadata,
  } = req.body;

  const connections = await connectionAPIController.getConnections({
    clientID,
  });

  if (!connections || connections.length === 0) {
    throw { message: 'Connection not found', statusCode: 404 };
  }

  const { isSAML, isOIDC } = strategyChecker(req);
  const { tenant, product, clientSecret } = connections[0];

  if (tenant !== setupLink.tenant || product !== setupLink.product) {
    throw { message: 'Tenant/Product mismatch', statusCode: 400 };
  }

  const body = {
    tenant,
    product,
    clientID,
    clientSecret,
    ...('deactivated' in req.body ? { deactivated } : undefined),
    ...(isSAML ? { metadataUrl, encodedRawMetadata, forceAuthn } : undefined),
    ...(isOIDC
      ? {
          oidcClientId,
          oidcClientSecret,
          oidcDiscoveryUrl,
          oidcMetadata,
        }
      : undefined),
  };

  if (isSAML) {
    await connectionAPIController.updateSAMLConnection(body as any);
  } else if (isOIDC) {
    await connectionAPIController.updateOIDCConnection(oidcMetadataParse(body as any));
  } else {
    throw { message: 'Missing SSO connection params', statusCode: 400 };
  }

  res.status(204).end();
};

export default handler;
