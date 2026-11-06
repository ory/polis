import type { NextApiRequest, NextApiResponse } from 'next';
import type { SetupLink } from '@boxyhq/saml-jackson';
import jackson from '@lib/jackson';
import { validateDevelopmentModeLimits } from '@lib/development-mode';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { method } = req;
  const { token } = req.query as { token: string };

  try {
    const setupLink = await setupLinkController.getByToken(token);

    switch (method) {
      case 'POST':
        return await handlePOST(req, res, setupLink);
      case 'GET':
        return await handleGET(req, res, setupLink);
      default:
        res.setHeader('Allow', 'PUT');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({ error: { message } });
  }
};

// Create a new configuration
const handlePOST = async (req: NextApiRequest, res: NextApiResponse, setupLink: SetupLink) => {
  const { directorySyncController } = await jackson();

  const { type } = req.body;

  await validateDevelopmentModeLimits(setupLink.product, 'dsync');

  const directory = {
    type,
    name: setupLink.name,
    tenant: setupLink.tenant,
    product: setupLink.product,
    webhook_url: setupLink.webhook_url,
    webhook_secret: setupLink.webhook_secret,
  };

  const { data, error } = await directorySyncController.directories.create(directory);

  if (data) {
    res.status(201).json({
      data: {
        id: data.id,
      },
    });
  }

  if (error) {
    res.status(error.code).json({ error });
  }
};

// Get all configurations
const handleGET = async (req: NextApiRequest, res: NextApiResponse, setupLink: SetupLink) => {
  const { directorySyncController } = await jackson();

  const { data, error } = await directorySyncController.directories.getByTenantAndProduct(
    setupLink.tenant,
    setupLink.product
  );

  if (data) {
    const directories = data.map((directory) => {
      return {
        id: directory.id,
        type: directory.type,
        name: directory.name,
        deactivated: directory.deactivated,
      };
    });

    res.json({ data: directories });
  }

  if (error) {
    res.status(error.code).json({ error });
  }
};

export default handler;
