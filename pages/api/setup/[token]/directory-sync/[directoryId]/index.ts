import type { NextApiRequest, NextApiResponse } from 'next';
import jackson from '@lib/jackson';

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  const { setupLinkController } = await jackson();

  const { method } = req;
  const { token } = req.query as { token: string };

  try {
    const setupLink = await setupLinkController.getByToken(token);

    switch (method) {
      case 'PATCH':
        return await handlePATCH(req, res, setupLink);
      case 'GET':
        return await handleGET(req, res, setupLink);
      case 'DELETE':
        return await handleDELETE(req, res, setupLink);
      default:
        res.setHeader('Allow', 'PATCH, GET, DELETE');
        res.status(405).json({ error: { message: `Method ${method} Not Allowed` } });
    }
  } catch (err: any) {
    const { message, statusCode = 500 } = err;

    return res.status(statusCode).json({ error: { message } });
  }
};

// Update a directory configuration
const handlePATCH = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { directorySyncController } = await jackson();

  const { directoryId } = req.query as { directoryId: string };
  const { deactivated } = req.body;

  const { data: directory } = await directorySyncController.directories.get(directoryId);

  if (directory?.tenant !== setupLink.tenant || directory?.product !== setupLink.product) {
    res.status(400).json({ error: { message: 'Tenant/Product mismatch' } });
  }

  const { data, error } = await directorySyncController.directories.update(directoryId, { deactivated });

  if (data) {
    res.json({ data: null });
  }

  if (error) {
    res.status(error.code).json({ error });
  }
};

// Get a directory configuration
const handleGET = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { directorySyncController } = await jackson();

  const { directoryId } = req.query as { directoryId: string };

  const { data, error } = await directorySyncController.directories.get(directoryId);

  if (data?.tenant !== setupLink.tenant || data?.product !== setupLink.product) {
    res.status(400).json({ error: { message: 'Tenant/Product mismatch' } });
  }

  if (data) {
    res.json({
      data: {
        id: data.id,
        type: data.type,
        name: data.name,
        deactivated: data.deactivated,
        scim: data.scim,
        google_authorized: data.google_access_token && data.google_refresh_token, // Indicate if the Google authorization is complete,
        google_authorization_url: data.google_authorization_url && data.google_authorization_url,
      },
    });
  }

  if (error) {
    res.status(error.code).json({ error });
  }
};

// Delete a directory configuration
const handleDELETE = async (req: NextApiRequest, res: NextApiResponse, setupLink: any) => {
  const { directorySyncController } = await jackson();

  const { directoryId } = req.query as { directoryId: string };

  const { data: directory } = await directorySyncController.directories.get(directoryId);

  if (directory?.tenant !== setupLink.tenant || directory?.product !== setupLink.product) {
    res.status(400).json({ error: { message: 'Tenant/Product mismatch' } });
  }

  const { error } = await directorySyncController.directories.delete(directoryId);

  if (error) {
    res.status(error.code).json({ error });
  }

  res.json({ data: null });
};

export default handler;
