import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { defaultHandler } from '@lib/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
    DELETE: handleDELETE,
  });
}

// Get webhook events
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const searchParams = req.query as {
    tenant: string;
    product: string;
    directoryId: string;
  };

  let tenant = searchParams.tenant || '';
  let product = searchParams.product || '';

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  // If tenant and product are not provided, retrieve the from directory
  if ((!tenant || !product) && searchParams.directoryId) {
    const { data: directory } = await directorySyncController.directories.get(searchParams.directoryId);

    if (!directory) {
      return res.status(404).json({ error: { message: 'Directory not found.' } });
    }

    tenant = directory.tenant;
    product = directory.product;
  }

  const events = await directorySyncController.webhookLogs.setTenantAndProduct(tenant, product).getAll({
    pageOffset,
    pageLimit,
    pageToken,
    directoryId: searchParams.directoryId,
  });

  return res.json(events);
};

// Delete webhook events for a directory
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { directoryId } = req.query as {
    directoryId: string;
  };

  const { data: directory, error } = await directorySyncController.directories.get(directoryId);

  if (error) {
    return res.status(error.code).json({ error });
  }

  await directorySyncController.webhookLogs
    .setTenantAndProduct(directory.tenant, directory.product)
    .deleteAll(directory.id);

  return res.json({ data: null });
};
