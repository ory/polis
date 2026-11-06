import type { NextPage, GetServerSidePropsContext } from 'next';
import { useRouter } from 'next/router';
import React from 'react';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import EditDirectory from '@components/dsync/EditDirectory';

const DirectoryEditPage: NextPage = () => {
  const router = useRouter();

  const { directoryId } = router.query as { directoryId: string };

  return <EditDirectory directoryId={directoryId} />;
};

export const getServerSideProps = async (context: GetServerSidePropsContext) => {
  const { locale } = context;

  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
};

export default DirectoryEditPage;
