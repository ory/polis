import type { GetServerSidePropsContext, NextPage } from 'next';
import CreateConnection from '@components/connection/CreateConnection';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import type { AdminPortalSSODefaults } from '@lib/utils';
import { adminPortalSSODefaults } from '@lib/env';

type Props = {
  adminPortalSSODefaults: AdminPortalSSODefaults;
};

const NewSSOConnection: NextPage<Props> = ({ adminPortalSSODefaults }) => {
  return <CreateConnection isSettingsView adminPortalSSODefaults={adminPortalSSODefaults} />;
};

export async function getServerSideProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
      adminPortalSSODefaults,
    },
  };
}

export default NewSSOConnection;
