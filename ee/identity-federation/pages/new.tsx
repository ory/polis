import { useRouter } from 'next/router';
import { useTranslation } from 'next-i18next';
import { errorToast, successToast } from '@components/Toaster';
import LicenseRequired from '@components/LicenseRequired';
import { NewIdentityFederationApp, LinkBack } from '@boxyhq/internal-ui';

import 'react-tagsinput/react-tagsinput.css';

const NewApp = ({ hasValidLicense, samlAudience }: { hasValidLicense: boolean; samlAudience: string }) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  if (!hasValidLicense) {
    return <LicenseRequired />;
  }

  return (
    <div className='space-y-4'>
      <LinkBack href='/admin/identity-federation' />
      <NewIdentityFederationApp
        urls={{ createApp: '/api/admin/identity-federation' }}
        onSuccess={(data) => {
          successToast(t('identity_federation_new_success'));
          router.replace(`/admin/identity-federation/${data.id}/edit`);
        }}
        onError={(error) => {
          errorToast(error.message);
        }}
        onEntityIdGenerated={() => {
          successToast(t('saml_federation_entity_id_generated'));
        }}
        samlAudience={samlAudience}
      />
    </div>
  );
};

export default NewApp;
