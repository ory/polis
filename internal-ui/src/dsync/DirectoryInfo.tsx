import { useTranslation } from 'next-i18next';
import ArrowTopRightOnSquareIcon from '@heroicons/react/24/outline/ArrowTopRightOnSquareIcon';

import { useDirectory } from '../hooks';
import { DirectoryTab } from '../dsync';
import type { Directory } from '../types';
import { Loading, Error, PageHeader, Badge, Alert, InputWithCopyButton, LinkPrimary } from '../shared';

type ExcludeFields = keyof Pick<Directory, 'id' | 'tenant' | 'product' | 'webhook'>;

export const DirectoryInfo = ({
  urls,
  excludeFields = [],
  hideTabs = false,
  displayGoogleAuthButton = false,
}: {
  urls: { getDirectory: string; tabBase: string };
  excludeFields?: ExcludeFields[];
  hideTabs?: boolean;
  displayGoogleAuthButton?: boolean;
}) => {
  const { t } = useTranslation('common');
  const { directory, isLoadingDirectory, directoryError } = useDirectory(urls.getDirectory);

  if (isLoadingDirectory) {
    return <Loading />;
  }

  if (directoryError) {
    return <Error message={directoryError.message} />;
  }

  if (!directory) {
    return null;
  }

  const authorizedGoogle =
    directory?.google_authorized || (directory?.google_access_token && directory?.google_refresh_token);
  const hideInfo = excludeFields.length === 4 && directory.type !== 'google';

  return (
    <>
      <PageHeader title={directory.name} />
      {!hideTabs && <DirectoryTab activeTab='directory' baseUrl={urls.tabBase} />}
      {directory.type === 'google' && !authorizedGoogle && displayGoogleAuthButton && (
        <div className='mt-5'>
          <Alert variant='success' className='bg-white border-error'>
            <div className='space-y-3'>
              <p className='text-sm text-gray-600'>{t('bui-dsync-authorization-google-desc')}</p>
              <LinkPrimary
                href={`${directory.google_authorization_url}?directoryId=${directory.id}`}
                target='_blank'
                className='btn-md'
                Icon={ArrowTopRightOnSquareIcon}
                rel='noopener noreferrer'>
                {t('bui-dsync-authorization-google')}
              </LinkPrimary>
            </div>
          </Alert>
        </div>
      )}
      {!hideInfo && (
        <div className={`rounded border ${hideTabs ? 'mt-5' : ''}`}>
          <dl className='divide-y'>
            {!excludeFields.includes('id') && (
              <div className='px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6'>
                <dt className='text-sm font-medium text-gray-500'>{t('bui-dsync-directory-id')}</dt>
                <dd className='mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0'>{directory.id}</dd>
              </div>
            )}
            {!excludeFields.includes('tenant') && (
              <div className='px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6'>
                <dt className='text-sm font-medium text-gray-500'>{t('bui-shared-tenant')}</dt>
                <dd className='mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0'>{directory.tenant}</dd>
              </div>
            )}
            {!excludeFields.includes('product') && (
              <div className='px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6'>
                <dt className='text-sm font-medium text-gray-500'>{t('bui-shared-product')}</dt>
                <dd className='mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0'>{directory.product}</dd>
              </div>
            )}
            {!excludeFields.includes('webhook') && (
              <>
                <div className='px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6'>
                  <dt className='text-sm font-medium text-gray-500'>{t('bui-dsync-webhook-endpoint')}</dt>
                  <dd className='mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0'>
                    {directory.webhook.endpoint || '-'}
                  </dd>
                </div>
                <div className='px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6'>
                  <dt className='text-sm font-medium text-gray-500'>{t('bui-shared-webhook-secret')}</dt>
                  <dd className='mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0'>
                    {directory.webhook.secret || '-'}
                  </dd>
                </div>
              </>
            )}
            {directory.type === 'google' && (
              <>
                <div className='px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6'>
                  <dt className='text-sm font-medium text-gray-500'>{t('bui-shared-status')}</dt>
                  <dd className='mt-1 text-sm text-gray-900 sm:col-span-2 sm:mt-0'>
                    {authorizedGoogle ? (
                      <Badge color='success'>{t('bui-dsync-authorized')}</Badge>
                    ) : (
                      <Badge color='warning'>{t('bui-dsync-not-authorized')}</Badge>
                    )}
                  </dd>
                </div>
              </>
            )}
          </dl>
        </div>
      )}
      {directory.scim.endpoint && directory.scim.secret && (
        <div className='mt-4 space-y-4 rounded border p-6'>
          <div className='form-control'>
            <InputWithCopyButton
              text={directory.scim.endpoint as string}
              label={t('bui-dsync-scim-endpoint')}
            />
          </div>
          <div className='form-control'>
            <InputWithCopyButton text={directory.scim.secret} label={t('bui-dsync-scim-token')} />
          </div>
        </div>
      )}
      {directory.type === 'google' && (
        <div className='form-control mt-6'>
          <InputWithCopyButton
            text={`${directory.google_authorization_url}?directoryId=${directory.id}`}
            label={t('bui-dsync-google-auth-url')}
          />
        </div>
      )}
    </>
  );
};
