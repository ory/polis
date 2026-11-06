import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { defaultHandler } from '@lib/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get the list of members (user_id only) in a group
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const searchParams = req.query as {
    tenant: string;
    product: string;
    directoryId: string;
    groupId: string;
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

  const { data, error } = await directorySyncController.groups
    .setTenantAndProduct(tenant, product)
    .getGroupMembers({
      groupId: searchParams.groupId,
      pageOffset,
      pageLimit,
      pageToken,
    });

  if (error) {
    return res.status(error.code).json({ error });
  }

  return res.json({ data });
};
