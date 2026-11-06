import type { GetServerSidePropsContext, NextPage } from 'next';
import useSWR from 'swr';
import { useRouter } from 'next/router';

import { fetcher } from '@lib/ui/utils';
import EditConnection from '@components/connection/EditConnection';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { Loading } from '@boxyhq/internal-ui';
import { errorToast } from '@components/Toaster';
import type { OIDCSSORecord, SAMLSSORecord } from '@boxyhq/saml-jackson';

const EditSSOConnection: NextPage = () => {
  const router = useRouter();

  const { id } = router.query as { id: string };

  const { data, error, isLoading } = useSWR<SAMLSSORecord | OIDCSSORecord>(
    id ? `/api/admin/connections/${id}` : null,
    fetcher,
    {
      revalidateOnFocus: false,
    }
  );

  if (isLoading) {
    return <Loading />;
  }

  if (error) {
    errorToast(error.message);
    return null;
  }

  if (!data) {
    return null;
  }

  return <EditConnection connection={data[0]} isSettingsView />;
};

export async function getServerSideProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default EditSSOConnection;
