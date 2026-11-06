import { NextPage } from 'next';
import { useRouter } from 'next/router';
import { SSOTraceInfo, LinkBack } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const SSOTraceInspector: NextPage = () => {
  const router = useRouter();

  const { traceId } = router.query as { traceId: string };

  return (
    <div className='space-y-4'>
      <LinkBack href='/admin/sso-traces' />
      <SSOTraceInfo urls={{ getTraces: `/api/admin/sso-traces/${traceId}` }} />
    </div>
  );
};

export default SSOTraceInspector;

export async function getServerSideProps({ locale }) {
  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
    },
  };
}
