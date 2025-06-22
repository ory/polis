/* eslint-disable @next/next/no-img-element */
import React from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import InvalidSetupLinkAlert from '@components/setup-link/InvalidSetupLinkAlert';
import { Loading } from '@boxyhq/internal-ui';
import useSetupLink from '@lib/ui/hooks/useSetupLink';
import { useTranslation } from 'next-i18next';
import { hexToOklch } from '@lib/color';
import { PoweredBy } from '@components/ProtectedBy';

export const SetupLinkLayout = ({ children }: { children: React.ReactNode }) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  const { token } = router.query as { token: string };

  const { setupLink, error, isLoading } = useSetupLink(token);

  if (isLoading) {
    return <Loading />;
  }

  const titles = {
    sso: t('configure_sso'),
    dsync: t('configure_dsync'),
  };

  const title = setupLink?.service ? titles[setupLink?.service] : '';

  return (
    <>
      <Head>
        <title>{`${title} - ${setupLink?.companyName}`}</title>
        {setupLink?.faviconUrl && <link rel='icon' href={setupLink.faviconUrl} />}
      </Head>

      {setupLink?.primaryColor && <style>{`:root { --p: ${hexToOklch(setupLink.primaryColor)}; }`}</style>}

      <div className='mx-auto p-6'>
        <div className='flex flex-1 flex-col'>
          <div className='top-0 flex h-16 flex-shrink-0 border-b'>
            <div className='flex flex-shrink-0 items-center gap-4 max-w-3xl'>
              <Link href={`/setup/${token}`}>
                {setupLink?.logoUrl && (
                  <img src={setupLink.logoUrl} alt={setupLink.companyName || ''} className='max-h-10' />
                )}
              </Link>
              <span className='text-xl font-bold tracking-wide text-gray-900'>{title}</span>
            </div>
          </div>
          <main>
            <div className='py-6'>
              {error && <InvalidSetupLinkAlert message={error.message} />}
              {setupLink && children}
            </div>
          </main>
        </div>
      </div>
      <PoweredBy />
    </>
  );
};
