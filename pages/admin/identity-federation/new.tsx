import { serverSideTranslations } from 'next-i18next/serverSideTranslations';

import jackson from '@lib/jackson';
import { jacksonOptions } from '@lib/env';

export { default } from '@ee/identity-federation/pages/new';

export async function getServerSideProps({ locale }) {
  const { checkLicense } = await jackson();

  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
      hasValidLicense: await checkLicense(),
      samlAudience: jacksonOptions.samlAudience || 'https://saml.boxyhq.com',
    },
  };
}
