import { defaultHandler } from '@lib/api';
import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get the sso traces filtered by the product
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { adminController } = await jackson();

  const { product } = req.query as {
    product: string;
  };

  const count = await adminController.countByProduct(product);

  res.json({ count });
};
