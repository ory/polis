import { useRouter } from 'next/router';
import { notFound } from 'next/navigation';
import { useTranslation } from 'next-i18next';
import type { SetupLinkService } from '@boxyhq/saml-jackson';
import { LinkBack, NewSetupLink } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import type { GetServerSidePropsContext, InferGetServerSidePropsType } from 'next';

import { setupLinkExpiryDays } from '@lib/env';
import { errorToast, successToast } from '@components/Toaster';

const serviceMap = {
  sso: 'sso-connection',
  dsync: 'directory-sync',
} as const;

const SetupLinkCreatePage = ({ expiryDays }: InferGetServerSidePropsType<typeof getServerSideProps>) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  let service: SetupLinkService | null = null;

  if (router.asPath.includes('sso-connection')) {
    service = 'sso';
  } else if (router.asPath.includes('directory-sync')) {
    service = 'dsync';
  }

  if (!service) {
    return notFound();
  }

  return (
    <div className='space-y-4'>
      <LinkBack href={`/admin/${serviceMap[service]}/setup-link`} />
      <NewSetupLink
        urls={{ createLink: '/api/admin/setup-links' }}
        service={service}
        expiryDays={expiryDays}
        onCreate={() => {
          successToast(t('setup-link-created'));
        }}
        onError={(error) => errorToast(error.message)}
      />
    </div>
  );
};

export async function getServerSideProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
      expiryDays: setupLinkExpiryDays,
    },
  };
}

export default SetupLinkCreatePage;
