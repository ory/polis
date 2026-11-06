import { useRouter } from 'next/router';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { DirectoryInfo, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const DirectoryInfoPage: NextPage = () => {
  const router = useRouter();

  const { directoryId } = router.query as { directoryId: string };

  return (
    <>
      <LinkBack href='/admin/directory-sync' className='mb-3' />
      <DirectoryInfo
        urls={{
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

export default DirectoryInfoPage;
