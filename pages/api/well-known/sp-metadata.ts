import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    throw { message: 'Method not allowed', statusCode: 405 };
  }

  const { encryption = 'false', entityId, acsUrl } = req.query;

  const { spConfig } = await jackson();

  res
    .status(200)
    .setHeader('Content-Type', 'text/xml')
    .send(
      await spConfig.toXMLMetadata(
        encryption === 'true',
        entityId as string | undefined,
        acsUrl as string | undefined
      )
    );
}
