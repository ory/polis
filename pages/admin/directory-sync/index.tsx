import type { GetStaticPropsContext, NextPage } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import DirectoryList from '@components/dsync/DirectoryList';

const DirectoryIndexPage: NextPage = () => {
  return <DirectoryList />;
};

export const getStaticProps = async (context: GetStaticPropsContext) => {
  const { locale } = context;

  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
};

export default DirectoryIndexPage;
