import type { NextApiRequest, NextApiResponse } from 'next';

import { boxyhqHosted, adminPortal } from '@lib/env';
import { getPortalBranding, getProductBranding } from '../utils';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { method } = req;

  try {
    switch (method) {
      case 'GET':
        await handleGET(req, res);
        break;
      default:
        res.setHeader('Allow', 'GET');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    res.status(statusCode).json({ error: { message } });
  }
};

const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { productId } = req.query as { productId: string };

  const productOrPortalBranding = boxyhqHosted
    ? await getProductBranding(productId)
    : await getPortalBranding();

  res.json({
    data: productOrPortalBranding,
    hideIdentityFederation: adminPortal.hideIdentityFederation,
    hideDirectorySync: adminPortal.hideDirectorySync,
  });
};

export default handler;
