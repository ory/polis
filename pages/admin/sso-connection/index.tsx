import type { GetServerSidePropsContext, NextPage } from 'next';
import ConnectionList from '@components/connection/ConnectionList';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const ConnectionsIndexPage: NextPage = () => {
  return <ConnectionList />;
};

export async function getStaticProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default ConnectionsIndexPage;
