import type { NextPage } from 'next';
import { useRouter } from 'next/router';
import React from 'react';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import EditDirectory from '@components/dsync/EditDirectory';

const DirectoryEditPage: NextPage = () => {
  const router = useRouter();

  const { token, directoryId } = router.query as { token: string; directoryId: string };

  return <EditDirectory directoryId={directoryId} setupLinkToken={token} />;
};

export const getServerSideProps = async (context) => {
  const { locale } = context;

  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
    },
  };
};

export default DirectoryEditPage;
