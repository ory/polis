import { useRouter } from 'next/router';
import { errorToast } from '@components/Toaster';
import { useTranslation } from 'next-i18next';
import { LinkBack } from '@boxyhq/internal-ui';
import { CreateSSOConnection } from '@boxyhq/react-ui/sso';
import { BOXYHQ_UI_CSS } from '@components/styles';
import { AdminPortalSSODefaults } from '@lib/utils';

const CreateConnection = ({
  isSettingsView = false,
  adminPortalSSODefaults,
}: {
  idpEntityID?: string;
  isSettingsView?: boolean;
  adminPortalSSODefaults?: AdminPortalSSODefaults;
}) => {
  const { t } = useTranslation('common');
  const router = useRouter();

  const redirectUrl = isSettingsView ? '/admin/settings/sso-connection' : '/admin/sso-connection';

  const backUrl = redirectUrl;

  const fieldsToExclude: any = isSettingsView ? ['label', 'tenant', 'product'] : ['label'];

  return (
    <>
      {backUrl && <LinkBack href={backUrl} />}
      <h2 className='mb-8 mt-5 font-bold text-gray-700 dark:text-white md:text-xl'>
        {t('create_sso_connection')}
      </h2>
      <div className='min-w-[28rem] rounded border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800'>
        <CreateSSOConnection
          defaults={isSettingsView ? adminPortalSSODefaults : undefined}
          variant={{ saml: 'advanced', oidc: 'advanced' }}
          urls={{
            post: '/api/admin/connections',
          }}
          excludeFields={{
            saml: fieldsToExclude,
            oidc: fieldsToExclude,
          }}
          successCallback={() => router.replace(redirectUrl)}
          errorCallback={(errMessage) => errorToast(errMessage)}
          classNames={BOXYHQ_UI_CSS}
        />
      </div>
    </>
  );
};

export default CreateConnection;
