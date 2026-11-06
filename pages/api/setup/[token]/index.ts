import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { boxyhqHosted } from '@lib/env';
import { getPortalBranding, getProductBranding } from '@ee/branding/utils';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { method } = req;

  try {
    switch (method) {
      case 'GET':
        return await handleGET(req, res);
      default:
        res.setHeader('Allow', 'GET');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({ error: { message } });
  }
};

// Get a setup link by token
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { token } = req.query as { token: string };

  const setupLink = await setupLinkController.getByToken(token);
  const branding = boxyhqHosted ? await getProductBranding(setupLink.product) : await getPortalBranding();

  return res.json({
    data: {
      ...setupLink,
      tenant: undefined,
      product: undefined,
      webhook_url: undefined,
      webhook_secret: undefined,
      ...branding,
    },
  });
};

export default handler;
