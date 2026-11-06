import type { NextApiRequest, NextApiResponse } from 'next';

import jackson from '@lib/jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { method } = req;

  if (method !== 'GET') {
    return res
      .setHeader('Allow', 'GET')
      .status(405)
      .json({ error: { message: `Method ${method} Not Allowed` } });
  }

  const { directoryId } = req.query as { directoryId: string };

  try {
    const { directorySyncController } = await jackson();

    const { data, error } = await directorySyncController.google.generateAuthorizationUrl({
      directoryId,
    });

    if (error) {
      throw error;
    }

    res.redirect(302, data.authorizationUrl).end();
    return;
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({ error: { message } });
  }
};

export default handler;
