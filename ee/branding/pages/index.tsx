import { BrandingForm, polisBranding } from '@boxyhq/internal-ui';
import LicenseRequired from '@components/LicenseRequired';
import { errorToast, successToast } from '@components/Toaster';
import { jacksonOptions } from '@lib/env';
import { useTranslation } from 'next-i18next';

const Branding = ({ hasValidLicense }: { hasValidLicense: boolean }) => {
  const { t } = useTranslation('common');

  if (!hasValidLicense) {
    return <LicenseRequired />;
  }

  return (
    <BrandingForm
      defaults={{
        primaryColor: polisBranding.primaryColor,
        logoUrl: polisBranding.logoUrl,
        faviconUrl: polisBranding.faviconUrl,
        companyName: polisBranding.companyName,
      }}
      urls={{
        getBranding: '/api/admin/branding',
        post: '/api/admin/branding',
        jacksonUrl: jacksonOptions.externalUrl,
      }}
      onUpdate={() => {
        successToast(t('settings_updated_successfully'));
      }}
      onError={(response) => {
        errorToast(response.message);
      }}
      title={t('settings_branding_title')}
      description={t('settings_branding_description')}
    />
  );
};

export default Branding;
