import type { NextPage } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import ConnectionList from '@components/connection/ConnectionList';
import { useRouter } from 'next/router';
import useIdpEntityID from '@lib/ui/hooks/useIdpEntityID';

const ConnectionsIndexPage: NextPage = () => {
  const router = useRouter();
  const { idpEntityID } = useIdpEntityID();

  const { token } = router.query as { token: string };

  return <ConnectionList setupLinkToken={token} idpEntityID={idpEntityID} />;
};

export async function getServerSideProps({ locale }) {
  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
    },
  };
}

export default ConnectionsIndexPage;
