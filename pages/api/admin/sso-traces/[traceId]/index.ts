import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
};

// Get SAML Trace by traceId
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { adminController } = await jackson();

  const { traceId } = req.query as { traceId: string };

  const trace = await adminController.getSSOTraceById(traceId);

  res.json({ data: trace });
};

export default handler;
