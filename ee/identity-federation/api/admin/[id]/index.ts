import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import { defaultHandler } from '@lib/api';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  await defaultHandler(req, res, {
    GET: handleGET,
    PATCH: handlePATCH,
    DELETE: handleDELETE,
  });
};

// Get Identity Federation app by id
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { identityFederationController } = await jackson();

  const { id } = req.query as { id: string };

  const app = await identityFederationController.app.get({ id });
  const metadata = await identityFederationController.app.getMetadata();

  res.json({
    data: {
      ...app,
      metadata,
    },
  });
};

// Update Identity Federation app
const handlePATCH = async (req: NextApiRequest, res: NextApiResponse) => {
  const { identityFederationController } = await jackson();

  const updatedApp = await identityFederationController.app.update(req.body);

  res.json({ data: updatedApp });
};

// Delete the Identity Federation app
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse) => {
  const { identityFederationController } = await jackson();

  const { id } = req.query as { id: string };

  await identityFederationController.app.delete({ id });

  res.json({ data: null });
};

export default handler;
