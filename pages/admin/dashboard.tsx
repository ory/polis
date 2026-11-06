import { WellKnownURLs } from '@boxyhq/internal-ui';
import type { GetServerSidePropsContext, InferGetServerSidePropsType, NextPage } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { adminPortal } from '@lib/env';

const Dashboard: NextPage<InferGetServerSidePropsType<typeof getStaticProps>> = ({
  hideIdentityFederation,
}) => {
  return <WellKnownURLs hideIdentityFederation={hideIdentityFederation} />;
};

export async function getStaticProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      hideIdentityFederation: adminPortal.hideIdentityFederation,
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default Dashboard;
