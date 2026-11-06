import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { ApiError } from '@lib/error';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
};

// Get the details of a group
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { directoryId, groupId } = req.query as { directoryId: string; groupId: string };

  const { data: directory, error } = await directorySyncController.directories.get(directoryId);

  if (error) {
    throw new ApiError(error.message, error.code);
  }

  const { data: group, error: groupError } = await directorySyncController.groups
    .setTenantAndProduct(directory.tenant, directory.product)
    .get(groupId);

  if (groupError) {
    throw new ApiError(groupError.message, groupError.code);
  }

  res.json({ data: group });
};

export default handler;
