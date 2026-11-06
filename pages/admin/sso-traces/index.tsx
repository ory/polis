import type { NextPage } from 'next';
import { useRouter } from 'next/router';
import { SSOTraces } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

const SSOTraceViewer: NextPage = () => {
  const router = useRouter();

  return (
    <SSOTraces
      urls={{ getTraces: '/api/admin/sso-traces' }}
      onView={(trace) => router.push(`/admin/sso-traces/${trace.traceId}/inspect`)}
    />
  );
};

export default SSOTraceViewer;

export async function getServerSideProps({ locale }) {
  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
    },
  };
}
