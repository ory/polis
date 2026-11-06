import { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { parsePaginateApiParams } from '@lib/utils';
import { defaultHandler } from '@lib/api';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Get SAML federated apps filtered by the product
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { identityFederationController } = await jackson();

  const { product } = req.query as {
    product: string;
  };

  const { pageOffset, pageLimit, pageToken } = parsePaginateApiParams(req.query);

  const apps = await identityFederationController.app.getByProduct({
    product,
    pageOffset,
    pageLimit,
    pageToken,
  });

  res.json(apps);
};
