import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';
import stream from 'stream';
import { promisify } from 'util';
import { defaultHandler } from '@lib/api';

const pipeline = promisify(stream.pipeline);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  await defaultHandler(req, res, {
    GET: handleGET,
  });
}

// Display the metadata for the SAML federation
const handleGET = async (req: NextApiRequest, res: NextApiResponse) => {
  const { identityFederationController } = await jackson();

  const { download, entityId } = req.query as { download: any; entityId?: string };

  try {
    const metadata = await identityFederationController.app.getMetadata(entityId);

    res.setHeader('Content-type', 'text/xml');

    if (download || download === '') {
      res.setHeader('Content-Disposition', `attachment; filename=saml-metadata.xml`);

      await pipeline(metadata.xml, res);
      return;
    }

    res.status(200).send(metadata.xml);
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({
      error: { message },
    });
  }
};
