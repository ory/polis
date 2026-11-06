import { defaultHandler } from '@lib/api';
import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get the saml trace by id
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { adminController } = await jackson();

  const { id } = req.query as { id: string };

  const trace = await adminController.getSSOTraceById(id);

  res.json({ data: trace });
};
