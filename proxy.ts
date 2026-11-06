import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { validateApiKey, extractAuthToken } from '@lib/auth';
import { getToken } from 'next-auth/jwt';
import { sessionName } from '@lib/constants';
import micromatch from 'micromatch';

// Add API routes that don't require authentication
const unAuthenticatedApiRoutes = [
  '/api/health',
  '/api/hello',
  '/api/auth/**',
  '/api/federated-saml/**',
  '/api/identity-federation/**',
  '/api/logout/**',
  '/api/oauth/**',
  '/api/scim/v2.0/**',
  '/api/scim/oauth/**',
  '/api/well-known/**',
  '/api/setup/**',
  '/api/branding',
  '/api/error',
];

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Bypass routes that don't require authentication
  if (micromatch.isMatch(pathname, unAuthenticatedApiRoutes)) {
    return NextResponse.next();
  }

  // Validate API routes `/api/admin/**`
  if (micromatch.isMatch(pathname, '/api/admin/**')) {
    const adminToken = await getToken({
      req,
      cookieName: sessionName,
    });

    if (!adminToken) {
      return sendUnAuthorizedResponse({ message: 'Unauthorized' });
    }

    return NextResponse.next();
  }

  // Validate API routes `/api/v1/**`
  if (micromatch.isMatch(pathname, ['/api/v1/**', '/api/internals/**'])) {
    if (!validateApiKey(extractAuthToken(req))) {
      return sendUnAuthorizedResponse({ message: 'Unauthorized' });
    }

    return NextResponse.next();
  }

  // By default, deny access to all other routes
  return sendUnAuthorizedResponse({ message: 'Unauthorized' });
}

// Send 401 response for unauthenticated requests
const sendUnAuthorizedResponse = async (error: { message: string }) => {
  const response = JSON.stringify({ error });

  return new NextResponse(response, {
    status: 401,
    headers: { 'content-type': 'application/json' },
  });
};

// Limit the middleware to specific '/api/*' routes
export const config = {
  matcher: ['/api/:path*'],
};
