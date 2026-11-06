import { useRouter } from 'next/router';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { DirectoryUsers, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const UsersList: NextPage = () => {
  const router = useRouter();

  const { directoryId } = router.query as {
    directoryId: string;
  };

  return (
    <>
      <LinkBack href='/admin/directory-sync' className='mb-3' />
      <DirectoryUsers
        urls={{
          getUsers: `/api/admin/directory-sync/${directoryId}/users`,
          getDirectory: `/api/admin/directory-sync/${directoryId}`,
          tabBase: `/admin/directory-sync/${directoryId}`,
        }}
        onView={(user) => router.push(`/admin/directory-sync/${directoryId}/users/${user.id}`)}
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

export default UsersList;
