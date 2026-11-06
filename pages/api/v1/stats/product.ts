import { defaultHandler } from '@lib/api';
import jackson from '@lib/jackson';
import { NextApiRequest, NextApiResponse } from 'next';
import { IndexNames } from 'npm/src/controller/utils';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    POST: handlePOST,
  });
}

const handlePOST = async (req: NextApiRequest, res: NextApiResponse) => {
  const { connectionAPIController, directorySyncController, identityFederationController } = await jackson();

  // Products must be an array of strings
  const products = req.body.products as string[];
  const type = req.body.type ? (req.body.type as 'sso' | 'dsync' | 'identityFederation') : undefined;

  // Validate products
  if (!products) {
    throw { message: 'Missing products', statusCode: 400 };
  } else if (!Array.isArray(products)) {
    throw { message: 'Products must be an array', statusCode: 400 };
  } else if (products.length > 50) {
    throw { message: 'Products must not exceed 50', statusCode: 400 };
  } else {
    // Get counts for product
    let sso_connections_count = 0;
    let dsync_connections_count = 0;
    let identity_federation_count = 0;

    for (const product of products) {
      if (product) {
        if (!type || type === 'sso') {
          const count = await connectionAPIController.getCount({ name: IndexNames.Product, value: product });
          sso_connections_count += count || 0;
        }

        if (!type || type === 'dsync') {
          const count = await directorySyncController.directories.getCount({
            name: IndexNames.Product,
            value: product,
          });
          dsync_connections_count += count || 0;
        }

        if (!type || type === 'identityFederation') {
          const count = await identityFederationController.app.getCount({
            name: IndexNames.Product,
            value: product,
          });
          identity_federation_count += count || 0;
        }
      }
    }

    return res.json({
      data: {
        sso_connections: sso_connections_count,
        dsync_connections: dsync_connections_count,
        identity_federation_apps: identity_federation_count,
      },
    });
  }
};
