import { defaultHandler } from '@lib/api';
import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
    DELETE: handleDELETE,
  });
}

// Get the sso traces filtered by the product
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { adminController } = await jackson();

  const { product } = req.query as {
    product: string;
  };

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const traces = await adminController.getTracesByProduct(product, pageOffset, pageLimit, pageToken);

  res.json(traces);
};

const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { adminController } = await jackson();

  const { product } = req.query as {
    product: string;
  };

  await adminController.deleteTracesByProduct(product);

  res.status(204).end();
};
