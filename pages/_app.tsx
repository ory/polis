import type { AppProps } from 'next/app';
import type { Session } from 'next-auth';
import type { NextPage } from 'next';
import { SessionProvider } from 'next-auth/react';
import { useRouter } from 'next/router';
import { Toaster } from '@components/Toaster';
import { appWithTranslation } from 'next-i18next';
import { ReactElement, ReactNode } from 'react';
import micromatch from 'micromatch';
import nextI18NextConfig from '../next-i18next.config.js';

import { AccountLayout, SetupLinkLayout } from '@components/layouts';
import '@boxyhq/react-ui/dist/react-ui.css';
import '../styles/globals.css';
import { BUIProvider } from '@boxyhq/internal-ui';

const unauthenticatedRoutes = [
  '/',
  '/admin/auth/login',
  '/admin/auth/idp-login',
  '/well-known/saml-configuration',
  '/well-known/oidc-configuration',
  '/well-known/idp-configuration',
  '/oauth/jwks',
  '/idp/select',
  '/error',
  '/well-known',
];

const isUnauthenticatedRoute = (pathname: string) => {
  return micromatch.isMatch(pathname, unauthenticatedRoutes);
};

function MyApp({ Component, pageProps }: AppPropsWithLayout) {
  const router = useRouter();
  const { pathname } = router;

  const { session, ...props } = pageProps;

  const getLayout = Component.getLayout;

  // If a page level layout exists, use it
  if (getLayout) {
    return (
      <>
        {getLayout(<Component {...props} />)}
        <Toaster />
      </>
    );
  }

  if (pathname.startsWith('/setup/')) {
    return (
      <SetupLinkLayout>
        <Component {...props} />
        <Toaster />
      </SetupLinkLayout>
    );
  }

  if (isUnauthenticatedRoute(pathname)) {
    return <Component {...props} />;
  }

  return (
    <BUIProvider value={{ router }}>
      <SessionProvider session={session}>
        <AccountLayout>
          <Component {...props} />
          <Toaster />
        </AccountLayout>
      </SessionProvider>
    </BUIProvider>
  );
}

export default appWithTranslation<never>(MyApp, nextI18NextConfig);

export type AppPropsWithLayout = AppProps & {
  Component: NextPageWithLayout;
  pageProps: { session?: Session };
};

export type NextPageWithLayout<P = Record<string, unknown>> = NextPage<P> & {
  getLayout?: (page: ReactElement) => ReactNode;
};
