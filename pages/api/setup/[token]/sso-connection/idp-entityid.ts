import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';
import type { SetupLink } from '@boxyhq/saml-jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { method } = req;
  const { token } = req.query as { token: string };

  try {
    const setupLink = await setupLinkController.getByToken(token);

    switch (method) {
      case 'GET':
        return await handleGET(req, res, setupLink);
      default:
        res.setHeader('Allow', 'GET');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({ error: { message } });
  }
};

const handleGET = async (req: NextApiRequest, res: NextApiResponse, setupLink: SetupLink) => {
  const { connectionAPIController } = await jackson();

  const idpEntityID = connectionAPIController.getIDPEntityID({
    tenant: setupLink.tenant,
    product: setupLink.product,
  });

  return res.json({ data: { idpEntityID } });
};

export default handler;
