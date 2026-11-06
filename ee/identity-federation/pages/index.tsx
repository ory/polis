import router from 'next/router';
import LicenseRequired from '@components/LicenseRequired';
import { IdentityFederationApps } from '@boxyhq/internal-ui';

const AppsList = ({ hasValidLicense }: { hasValidLicense: boolean }) => {
  if (!hasValidLicense) {
    return <LicenseRequired />;
  }

  return (
    <IdentityFederationApps
      urls={{ getApps: '/api/admin/identity-federation' }}
      onEdit={(app) => router.push(`/admin/identity-federation/${app.id}/edit`)}
      actions={{
        newApp: '/admin/identity-federation/new',
        samlConfiguration: '/.well-known/idp-configuration',
        oidcConfiguration: '/.well-known/openid-configuration',
      }}
    />
  );
};

export default AppsList;
