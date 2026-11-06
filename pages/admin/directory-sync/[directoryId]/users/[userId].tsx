import { useRouter } from 'next/router';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { DirectoryUserInfo, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const UserInfo: NextPage = () => {
  const router = useRouter();

  const { directoryId, userId } = router.query as {
    directoryId: string;
    userId: string;
  };

  return (
    <>
      <LinkBack href={`/admin/directory-sync/${directoryId}/users`} className='mb-3' />
      <DirectoryUserInfo
        urls={{
          getUser: `/api/admin/directory-sync/${directoryId}/users/${userId}`,
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

export default UserInfo;
