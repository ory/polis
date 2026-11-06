import { useRouter } from 'next/router';
import { useTranslation } from 'next-i18next';
import { errorToast, successToast } from '@components/Toaster';
import LicenseRequired from '@components/LicenseRequired';
import { EditIdentityFederationApp, LinkBack } from '@boxyhq/internal-ui';

import 'react-tagsinput/react-tagsinput.css';

const UpdateApp = ({ hasValidLicense, jacksonUrl }: { hasValidLicense: boolean; jacksonUrl: string }) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  const { id } = router.query as { id: string };

  if (!hasValidLicense) {
    return <LicenseRequired />;
  }

  return (
    <div className='space-y-4'>
      <LinkBack href='/admin/identity-federation' />
      <EditIdentityFederationApp
        urls={{
          getApp: `/api/admin/identity-federation/${id}`,
          updateApp: `/api/admin/identity-federation/${id}`,
          deleteApp: `/api/admin/identity-federation/${id}`,
          jacksonUrl,
        }}
        onUpdate={() => {
          successToast(t('identity_federation_update_success'));
        }}
        onDelete={() => {
          successToast(t('identity_federation_delete_success'));
          router.push('/admin/identity-federation');
        }}
        onError={(error) => {
          errorToast(error.message);
        }}
      />
    </div>
  );
};

export default UpdateApp;
