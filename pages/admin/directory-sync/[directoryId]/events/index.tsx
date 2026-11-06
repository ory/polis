import { useRouter } from 'next/router';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { DirectoryWebhookLogs, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const Events: NextPage = () => {
  const router = useRouter();

  const { directoryId } = router.query as {
    directoryId: string;
  };

  return (
    <>
      <LinkBack href='/admin/directory-sync' className='mb-3' />
      <DirectoryWebhookLogs
        urls={{
          getEvents: `/api/admin/directory-sync/${directoryId}/events`,
          getDirectory: `/api/admin/directory-sync/${directoryId}`,
          tabBase: `/admin/directory-sync/${directoryId}`,
          deleteEvents: `/api/admin/directory-sync/${directoryId}/events`,
        }}
        onView={(event) => router.push(`/admin/directory-sync/${directoryId}/events/${event.id}`)}
        onDelete={() => router.reload()}
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

export default Events;
