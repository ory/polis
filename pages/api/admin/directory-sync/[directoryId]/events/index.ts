import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { ApiError } from '@lib/error';
import { parsePaginateApiParams } from '@lib/utils';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
    DELETE: handleDELETE,
  });
};

// Get all events
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { directoryId } = req.query as { directoryId: string };

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const { data: directory, error } = await directorySyncController.directories.get(directoryId);

  if (error) {
    throw new ApiError(error.message, error.code);
  }

  const result = await directorySyncController.webhookLogs
    .setTenantAndProduct(directory.tenant, directory.product)
    .getAll({
      pageOffset,
      pageLimit,
      pageToken,
      directoryId,
    });

  if (result.pageToken) {
    res.setHeader('jackson-pagetoken', result.pageToken);
  }

  res.json({ data: result.data });
};

// Delete all events
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { directoryId } = req.query as { directoryId: string };

  const { data: directory, error } = await directorySyncController.directories.get(directoryId);

  if (error) {
    throw new ApiError(error.message, error.code);
  }

  await directorySyncController.webhookLogs
    .setTenantAndProduct(directory.tenant, directory.product)
    .deleteAll(directoryId);

  res.json({ data: null });
};

export default handler;
