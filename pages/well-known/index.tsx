import { WellKnownURLs } from '@boxyhq/internal-ui';
import type { NextPage, GetServerSidePropsContext, InferGetServerSidePropsType } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { adminPortal } from '@lib/env';

const WellKnownURLsIndex: NextPage<InferGetServerSidePropsType<typeof getStaticProps>> = ({
  hideIdentityFederation,
}) => {
  return (
    <div className='mx-auto max-w-5xl px-4 py-10'>
      <WellKnownURLs hideIdentityFederation={hideIdentityFederation} />
    </div>
  );
};

export async function getStaticProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      hideIdentityFederation: adminPortal.hideIdentityFederation,
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default WellKnownURLsIndex;
