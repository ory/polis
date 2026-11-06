import type { NextApiRequest, NextApiResponse } from 'next';
import type { SetupLinkService } from '@boxyhq/saml-jackson';
import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';
import { normalizeBooleanParam } from '@lib/api/utils';

const service: SetupLinkService = 'sso';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
    POST: handlePOST,
    DELETE: handleDELETE,
  });
}

// Get the setup link by ID or (tenant + product + service) combination
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { id, tenant, product } = req.query as {
    id: string;
    tenant: string;
    product: string;
  };

  // Get by id
  if (id) {
    const setupLink = await setupLinkController.get(id);

    res.json({ data: setupLink });
  }

  // Get by tenant + product
  if (tenant && product) {
    const { data: setupLinks } = await setupLinkController.filterBy({
      tenant,
      product,
      service,
    });

    res.json({ data: setupLinks[0] });
  }
};

// Create a setup link
const handlePOST = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const body = { ...req.body };
  if ('regenerate' in req.body) {
    body.regenerate = normalizeBooleanParam(req.body.regenerate);
  }

  const setupLink = await setupLinkController.create({
    ...body,
    service,
  });

  res.status(201).json({ data: setupLink });
};

// Delete a setup link by ID or (tenant + product + service) combination
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { id, tenant, product } = req.query as {
    id: string;
    tenant: string;
    product: string;
  };

  if (id) {
    await setupLinkController.remove({ id });
  } else if (service && tenant && product) {
    await setupLinkController.remove({ service, tenant, product });
  }

  res.json({ data: {} });
};
