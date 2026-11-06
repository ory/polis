import { useRouter } from 'next/router';
import type { NextPage, GetServerSidePropsContext } from 'next';
import { DirectoryGroupInfo, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const GroupInfo: NextPage = () => {
  const router = useRouter();

  const { directoryId, groupId } = router.query as {
    directoryId: string;
    groupId: string;
  };

  return (
    <>
      <LinkBack href={`/admin/directory-sync/${directoryId}/groups`} className='mb-3' />
      <DirectoryGroupInfo
        urls={{
          getGroup: `/api/admin/directory-sync/${directoryId}/groups/${groupId}`,
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

export default GroupInfo;
