import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { parsePaginateApiParams } from '@lib/utils';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
};

// Get SAML Traces
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { adminController } = await jackson();

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const tracesPaginated = await adminController.getAllSSOTraces(pageOffset, pageLimit, pageToken);

  if (tracesPaginated.pageToken) {
    res.setHeader('jackson-pagetoken', tracesPaginated.pageToken);
  }

  res.json({ data: tracesPaginated.data });
};

export default handler;
