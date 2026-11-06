import React from 'react';
import { useRouter } from 'next/router';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { DirectoryWebhookLogInfo, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const EventInfo: NextPage = () => {
  const router = useRouter();

  const { directoryId, eventId } = router.query as {
    directoryId: string;
    eventId: string;
  };

  return (
    <>
      <LinkBack href={`/admin/directory-sync/${directoryId}/events`} className='mb-3' />
      <DirectoryWebhookLogInfo
        urls={{
          getEvent: `/api/admin/directory-sync/${directoryId}/events/${eventId}`,
          getDirectory: `/api/admin/directory-sync/${directoryId}`,
          tabBase: `/admin/directory-sync/${directoryId}`,
        }}
      />
    </>
  );
};

export const getServerSideProps = async (context: GetServerSidePropsContext) => {
  const { locale } = context;

  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
};

export default EventInfo;
