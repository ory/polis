import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get webhook events
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const searchParams = req.query as {
    tenant: string;
    product: string;
    directoryId: string;
    eventId: string;
  };

  let tenant = searchParams.tenant || '';
  let product = searchParams.product || '';

  // If tenant and product are not provided, retrieve the from directory
  if ((!tenant || !product) && searchParams.directoryId) {
    const { data: directory } = await directorySyncController.directories.get(searchParams.directoryId);

    if (!directory) {
      return res.status(404).json({ error: { message: 'Directory not found.' } });
    }

    tenant = directory.tenant;
    product = directory.product;
  }

  const event = await directorySyncController.webhookLogs
    .setTenantAndProduct(tenant, product)
    .get(searchParams.eventId);

  return res.json({ data: event });
};
