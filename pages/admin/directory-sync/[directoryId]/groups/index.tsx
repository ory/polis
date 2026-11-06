import { useRouter } from 'next/router';
import { DirectoryGroups, LinkBack } from '@boxyhq/internal-ui';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const GroupsList: NextPage = () => {
  const router = useRouter();

  const { directoryId } = router.query as {
    directoryId: string;
  };

  return (
    <>
      <LinkBack href='/admin/directory-sync' className='mb-3' />
      <DirectoryGroups
        urls={{
          getGroups: `/api/admin/directory-sync/${directoryId}/groups`,
          getDirectory: `/api/admin/directory-sync/${directoryId}`,
          tabBase: `/admin/directory-sync/${directoryId}`,
        }}
        onView={(group) => router.push(`/admin/directory-sync/${directoryId}/groups/${group.id}`)}
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

export default GroupsList;
