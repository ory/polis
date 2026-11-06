import { defaultHandler } from '@lib/api';
import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get the connections filtered by the product
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { directorySyncController } = await jackson();

  const { product } = req.query as {
    product: string;
  };

  if (!product) {
    throw new Error('Please provide a product');
  }

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const connections = await directorySyncController.directories.filterBy({
    product,
    pageOffset,
    pageLimit,
    pageToken,
  });

  return res.status(200).json(connections);
};
