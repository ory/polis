import type { GetServerSidePropsContext, NextPage } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import ConnectionList from '@components/connection/ConnectionList';

const ConnectionsIndexPageForSettings: NextPage = () => {
  return <ConnectionList isSettingsView={true} />;
};

export default ConnectionsIndexPageForSettings;

export async function getStaticProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}
