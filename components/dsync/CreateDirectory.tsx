import { useTranslation } from 'next-i18next';
import { useRouter } from 'next/router';
import React from 'react';
import { errorToast, successToast } from '@components/Toaster';
import { LinkBack } from '@boxyhq/internal-ui';
import { CreateDirectory as CreateDSync } from '@boxyhq/react-ui/dsync';
import { BOXYHQ_UI_CSS } from '@components/styles';

interface CreateDirectoryProps {
  setupLinkToken?: string;
  defaultWebhookEndpoint?: string;
  defaultWebhookSecret?: string;
}

const CreateDirectory = ({
  setupLinkToken,
  defaultWebhookEndpoint,
  defaultWebhookSecret,
}: CreateDirectoryProps) => {
  const { t } = useTranslation('common');
  const router = useRouter();

  const backUrl = setupLinkToken ? `/setup/${setupLinkToken}/directory-sync` : '/admin/directory-sync';

  return (
    <div>
      <LinkBack href={backUrl} />
      <h2 className='mb-5 mt-5 font-bold text-gray-700 md:text-xl'>{t('create_dsync_connection')}</h2>
      <div className='min-w-[28rem] rounded border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800'>
        <CreateDSync
          displayHeader={false}
          defaultWebhookEndpoint={defaultWebhookEndpoint}
          defaultWebhookSecret={defaultWebhookSecret}
          classNames={BOXYHQ_UI_CSS}
          successCallback={({ connection }) => {
            successToast(t('directory_created_successfully'));
            connection?.id &&
              router.replace(
                setupLinkToken
                  ? `/setup/${setupLinkToken}/directory-sync/${connection.id}`
                  : `/admin/directory-sync/${connection.id}`
              );
          }}
          errorCallback={(errorMessage) => {
            errorToast(errorMessage);
          }}
          excludeFields={
            setupLinkToken
              ? ['name', 'tenant', 'product', 'webhook_url', 'webhook_secret', 'log_webhook_events']
              : ['log_webhook_events']
          }
          urls={{
            post: setupLinkToken
              ? `/api/setup/${setupLinkToken}/directory-sync`
              : '/api/admin/directory-sync',
          }}
        />
      </div>
    </div>
  );
};

export default CreateDirectory;
