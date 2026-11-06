import type { NextApiRequest, NextApiResponse } from 'next';
import type { SetupLinkService } from '@boxyhq/saml-jackson';
import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { defaultHandler } from '@lib/api';

const service: SetupLinkService = 'dsync';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get the setup links filtered by the product
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { product } = req.query as {
    product: string;
  };

  if (!product) {
    throw new Error('Please provide a product');
  }

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const setupLinks = await setupLinkController.filterBy({
    product,
    service,
    pageOffset,
    pageLimit,
    pageToken,
  });

  res.json(setupLinks);
};
