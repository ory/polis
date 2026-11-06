import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { ApiError } from '@lib/error';
import { parsePaginateApiParams } from '@lib/utils';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
    POST: handlePOST,
    DELETE: handleDELETE,
  });
};

// Create a new setup link
const handlePOST = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const setupLink = await setupLinkController.create(req.body);

  res.status(201).json({ data: setupLink });
};

const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { id } = req.query as { id: string };

  await setupLinkController.remove({ id });

  res.json({ data: {} });
};

const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { token, service } = req.query as {
    token: string;
    service: string;
  };

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  if (!token && !service) {
    throw new ApiError('Either token or service is required', 400);
  }

  // Get a setup link by token
  if (token) {
    const setupLink = await setupLinkController.getByToken(token);

    res.json({ data: setupLink });
  }

  // Get a setup link by service
  else if (service) {
    const setupLinksPaginated = await setupLinkController.filterBy({
      service: service as any,
      pageOffset,
      pageLimit,
      pageToken,
    });

    if (setupLinksPaginated.pageToken) {
      res.setHeader('jackson-pagetoken', setupLinksPaginated.pageToken);
    }

    res.json({ data: setupLinksPaginated.data });
  }
};

export default handler;
