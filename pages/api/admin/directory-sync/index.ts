import type { NextApiRequest, NextApiResponse } from 'next';
import type { DirectoryType } from '@boxyhq/saml-jackson';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { ApiError } from '@lib/error';
import { parsePaginateApiParams } from '@lib/utils';
import { validateDevelopmentModeLimits } from '@lib/development-mode';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
    POST: handlePOST,
  });
};

const handlePOST = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { name, tenant, product, type, webhook_url, webhook_secret } = req.body;

  await validateDevelopmentModeLimits(product, 'dsync');

  const { data, error } = await directorySyncController.directories.create({
    name,
    tenant,
    product,
    type: type as DirectoryType,
    webhook_url,
    webhook_secret,
  });

  if (error) {
    throw new ApiError(error.message, error.code);
  }

  res.status(201).json({ data });
};

const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const {
    data,
    error,
    pageToken: nextPageToken,
  } = await directorySyncController.directories.getAll({
    pageOffset,
    pageLimit,
    pageToken,
  });

  if (nextPageToken) {
    res.setHeader('jackson-pagetoken', nextPageToken);
  }

  if (error) {
    throw new ApiError(error.message, error.code);
  }

  res.json({ data });
};

export default handler;
