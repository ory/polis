import type { GetServerSidePropsContext, NextPage } from 'next';
import CreateConnection from '@components/connection/CreateConnection';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const NewConnection: NextPage = () => {
  return <CreateConnection />;
};

export async function getStaticProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default NewConnection;
