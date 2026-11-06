import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { defaultHandler } from '@lib/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get the users
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

  const users = await directorySyncController.users.setTenantAndProduct(tenant, product).getAll({
    pageOffset,
    pageLimit,
    pageToken,
    directoryId: searchParams.directoryId,
  });

  if (users.error) {
    return res.status(users.error.code).json({ error: users.error });
  }

  return res.status(200).json(users);
};
