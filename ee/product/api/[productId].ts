import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    switch (req.method) {
      case 'GET':
        await handleGET(req, res);
        break;
      case 'DELETE':
        await handleDELETE(req, res);
        break;
      default:
        res.setHeader('Allow', 'GET,DELETE');
        res.status(405).json({ error: { message: `Method ${req.method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;
    res.status(statusCode).json({ error: { message } });
  }
};

// Fetch product configuration
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { productController } = await jackson();

  const { productId } = req.query as { productId: string };

  const product = await productController.get(productId);

  res.json({ data: product });
};

// delete product configuration
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { productController } = await jackson();

  const { productId } = req.query as { productId: string };

  await productController.delete(productId);

  res.status(204).end();
};

export default handler;
