import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { method } = req;
  const { token } = req.query as { token: string };

  try {
    const setupLink = await setupLinkController.getByToken(token);

    switch (method) {
      case 'GET':
        return await handleGET(req, res, setupLink);
      default:
        res.setHeader('Allow', 'GET');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({ error: { message } });
  }
};

const handleGET = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { connectionAPIController } = await jackson();

  const { id } = req.query as { id: string };

  const connections = await connectionAPIController.getConnections({
    clientID: id,
  });

  if (!connections || connections.length === 0) {
    res.status(404).json({ error: { message: 'Connection not found.' } });
  }

  const connection = connections[0];

  if (connection.tenant !== setupLink.tenant || connection.product !== setupLink.product) {
    res.status(400).json({ error: { message: 'Tenant/Product mismatch' } });
  }

  res.json([
    {
      clientID: connection.clientID,
      clientSecret: connection.clientSecret,
      deactivated: connection.deactivated,
      ...('forceAuthn' in connection ? { forceAuthn: connection.forceAuthn } : undefined),
      ...('idpMetadata' in connection ? { idpMetadata: {}, metadataUrl: connection.metadataUrl } : undefined),
      ...('oidcProvider' in connection ? { oidcProvider: connection.oidcProvider } : undefined),
    },
  ]);
};

export default handler;
