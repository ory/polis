import { useRouter } from 'next/router';
import { notFound } from 'next/navigation';
import { useTranslation } from 'next-i18next';
import { SetupLinks } from '@boxyhq/internal-ui';
import type { SetupLinkService } from '@boxyhq/saml-jackson';
import type { GetServerSidePropsContext, NextPage } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

import { errorToast, successToast } from '@components/Toaster';

const serviceMap = {
  sso: 'sso-connection',
  dsync: 'directory-sync',
} as const;

const SetupLinksIndexPage: NextPage = () => {
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
    <SetupLinks
      service={service}
      urls={{
        getLinks: '/api/admin/setup-links',
        deleteLink: '/api/admin/setup-links',
        regenerateLink: '/api/admin/setup-links',
      }}
      actions={{ newLink: `/admin/${serviceMap[service]}/setup-link/new` }}
      onCopy={() => {
        successToast(t('setup-link-copied'));
      }}
      onRegenerate={() => {
        successToast(t('setup-link-regenerated'));
      }}
      onDelete={() => {
        successToast(t('setup-link-deleted'));
      }}
      onError={(error) => {
        errorToast(error.message);
      }}
    />
  );
};

export async function getStaticProps({ locale }: GetServerSidePropsContext) {
  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default SetupLinksIndexPage;
