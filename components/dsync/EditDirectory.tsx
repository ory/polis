import { useRouter } from 'next/router';
import React from 'react';
import { useTranslation } from 'next-i18next';
import { errorToast, successToast } from '@components/Toaster';
import { LinkBack } from '@boxyhq/internal-ui';
import { EditDirectory as EditDSync } from '@boxyhq/react-ui/dsync';
import { BOXYHQ_UI_CSS } from '@components/styles';

const EditDirectory = ({ directoryId, setupLinkToken }: { directoryId: string; setupLinkToken?: string }) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  const backUrl = setupLinkToken ? `/setup/${setupLinkToken}/directory-sync` : '/admin/directory-sync';

  const apiUrl = setupLinkToken
    ? `/api/setup/${setupLinkToken}/directory-sync/${directoryId}`
    : `/api/admin/directory-sync/${directoryId}`;
  const redirectUrl = setupLinkToken ? `/setup/${setupLinkToken}/directory-sync` : '/admin/directory-sync';

  return (
    <div>
      <LinkBack href={backUrl} />
      <div className='flex items-center justify-between'>
        <h2 className='mb-5 mt-5 font-bold text-gray-700 md:text-xl'>{t('edit_directory')}</h2>
      </div>
      <div className='rounded border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800'>
        <EditDSync
          displayHeader={false}
          urls={{
            patch: apiUrl,
            delete: apiUrl,
            get: apiUrl,
          }}
          excludeFields={
            setupLinkToken
              ? [
                  'name',
                  'product',
                  'log_webhook_events',
                  'tenant',
                  'type',
                  'webhook_url',
                  'webhook_secret',
                  'scim_endpoint',
                  'scim_token',
                  'google_authorization_url',
                ]
              : undefined
          }
          successCallback={() => {
            successToast(t('directory_updated_successfully'));
            router.replace(redirectUrl);
          }}
          errorCallback={(errMessage) => {
            errorToast(errMessage);
          }}
          hideSave={setupLinkToken ? true : false}
          classNames={BOXYHQ_UI_CSS}
        />
      </div>
    </div>
  );
};

export default EditDirectory;
