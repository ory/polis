import type { NextApiRequest, NextApiResponse } from 'next';
import micromatch from 'micromatch';
import type { OIDCSSOConnectionWithDiscoveryUrl, OIDCSSOConnectionWithMetadata } from '@boxyhq/saml-jackson';
import { JacksonError } from 'npm/src/controller/error';
import type { PaginateApiParams } from 'types';
import { jacksonOptions } from '@lib/env';

export const validateEmailWithACL = (email: string) => {
  const NEXTAUTH_ACL = process.env.NEXTAUTH_ACL || undefined;

  if (!NEXTAUTH_ACL) {
    return false;
  }

  const acl = NEXTAUTH_ACL.split(',');

  return micromatch.isMatch(email, acl);
};

/**
 * This sets `cookie` using the `res` object
 */
export const setErrorCookieAndRedirect = (res: NextApiResponse, value: unknown) => {
  const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
  let cookieContents = 'polis_error' + '=' + encodeURIComponent(stringValue);
  let path = jacksonOptions.jsonErrorPage ? '/api/error' : '/error';

  if (jacksonOptions.externalUrl) {
    const url = new URL(jacksonOptions.externalUrl);
    path = url.pathname.endsWith('/') ? url.pathname + path.slice(1) : url.pathname + path;
  }

  cookieContents += '; Path=' + path;
  res.setHeader('Set-Cookie', cookieContents);
  res.redirect(302, path);
};

export const getErrorMessageFromCookie = (cookie: string | undefined) => {
  const error = {} as { statusCode: number | null; message: string; statusText?: string };
  try {
    const { statusCode, message } = JSON.parse(cookie!);
    error.statusCode = statusCode;
    error.message = message;

    if (typeof statusCode === 'number') {
      if (statusCode >= 400 && statusCode <= 499) {
        error.statusText = 'client_error';
      }
      if (statusCode >= 500 && statusCode <= 599) {
        error.statusText = 'server_error';
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (err) {
    console.error('Unknown error format');
  }
  return error;
};

const IsJsonString = (body: any): boolean => {
  try {
    const json = JSON.parse(body);

    return typeof json === 'object';
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (e) {
    return false;
  }
};

export const bodyParser = (req: NextApiRequest): any => {
  return IsJsonString(req.body) ? JSON.parse(req.body) : req.body;
};

export const strategyChecker = (req: NextApiRequest): { isSAML: boolean; isOIDC: boolean } => {
  const isSAML =
    'rawMetadata' in req.body ||
    'encodedRawMetadata' in req.body ||
    'metadataUrl' in req.body ||
    'isSAML' in req.body;

  const isOIDC = 'oidcDiscoveryUrl' in req.body || 'oidcMetadata' in req.body || 'isOIDC' in req.body;

  return { isSAML, isOIDC };
};

// The oidcMetadata JSON will be parsed here
export const oidcMetadataParse = (
  body: (
    | OIDCSSOConnectionWithDiscoveryUrl
    | (Omit<OIDCSSOConnectionWithMetadata, 'oidcMetadata'> & { oidcMetadata: string })
  ) & {
    clientID: string;
    clientSecret: string;
  }
) => {
  if (!body.oidcDiscoveryUrl && typeof body.oidcMetadata === 'string') {
    try {
      const oidcMetadata = JSON.parse(body.oidcMetadata);
      return { ...body, oidcMetadata };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err) {
      throw new JacksonError('Could not parse OIDC Provider metadata, expected a valid JSON string', 400);
    }
  }
  return body;
};

export const parsePaginateApiParams = (params: NextApiRequest['query']): PaginateApiParams => {
  let pageOffset, pageLimit;

  if ('pageOffset' in params) {
    pageOffset = params.pageOffset;
  } else if ('offset' in params) {
    pageOffset = params.offset;
  }

  if ('pageLimit' in params) {
    pageLimit = params.pageLimit;
  } else if ('limit' in params) {
    pageLimit = params.limit;
  }

  pageOffset = parseInt(pageOffset);
  pageLimit = parseInt(pageLimit);
  const pageToken = params.pageToken as string;

  return {
    pageOffset,
    pageLimit,
    pageToken,
  };
};

export type AdminPortalSSODefaults = {
  tenant: string;
  product: string;
  redirectUrl: string[];
  defaultRedirectUrl: string;
};
