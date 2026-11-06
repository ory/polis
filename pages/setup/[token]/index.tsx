import { useEffect } from 'react';
import type { NextPage } from 'next';
import { useRouter } from 'next/router';
import { Loading } from '@boxyhq/internal-ui';
import useSetupLink from '@lib/ui/hooks/useSetupLink';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const SetupLinkIndexPage: NextPage = () => {
  const router = useRouter();

  const { token } = router.query as { token: string };

  const { setupLink, isLoading } = useSetupLink(token);

  const service = setupLink?.service;

  useEffect(() => {
    if (service === 'sso') {
      router.replace(`/setup/${token}/sso-connection`);
    }
    if (service === 'dsync') {
      router.replace(`/setup/${token}/directory-sync`);
    }
  }, [router, service, token]);

  if (isLoading) {
    return <Loading />;
  }

  return null;
};

export const getServerSideProps = async (context) => {
  const { locale } = context;

  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
    },
  };
};

export default SetupLinkIndexPage;
