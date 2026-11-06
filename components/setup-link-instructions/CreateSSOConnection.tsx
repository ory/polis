import { useRouter } from 'next/router';

import { CreateSAMLConnection as CreateSAML, CreateOIDCConnection as CreateOIDC } from '@boxyhq/react-ui/sso';
import { errorToast, successToast } from '@components/Toaster';
import { useTranslation } from 'next-i18next';
import { BOXYHQ_UI_CSS } from '@components/styles';

interface CreateSSOConnectionProps {
  setupLinkToken: string;
  idpType: 'saml' | 'oidc';
}

const CreateSSOConnection = ({ setupLinkToken, idpType }: CreateSSOConnectionProps) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  const onSuccess = () => {
    successToast(t('sso_connection_created_successfully'));
    router.push({
      pathname: '/setup/[token]/sso-connection',
      query: { token: setupLinkToken },
    });
  };

  const onError = (message: string) => {
    errorToast(message);
  };

  const urls = {
    post: `/api/setup/${setupLinkToken}/sso-connection`,
  };

  return idpType === 'saml' ? (
    <CreateSAML
      variant='basic'
      urls={urls}
      successCallback={onSuccess}
      errorCallback={onError}
      classNames={BOXYHQ_UI_CSS}
      displayHeader={false}
    />
  ) : (
    <CreateOIDC
      variant='basic'
      urls={urls}
      successCallback={onSuccess}
      errorCallback={onError}
      classNames={BOXYHQ_UI_CSS}
      displayHeader={false}
    />
  );
};

export default CreateSSOConnection;
