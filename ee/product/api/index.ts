import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    switch (req.method) {
      case 'PATCH':
        await handlePATCH(req, res);
        break;
      default:
        res.setHeader('Allow', 'POST');
        res.status(405).json({ error: { message: `Method ${req.method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;
    res.status(statusCode).json({ error: { message } });
  }
};

// Update product configuration
const handlePATCH = async (req: NextApiRequest, res: NextApiResponse) => {
  const { productController } = await jackson();

  await productController.upsert(req.body);

  res.end();
};

export default handler;
