import useSWR from 'swr';
import type { IdentityFederationApp } from '../types';
import { Edit } from './Edit';
import { EditAttributesMapping } from './EditAttributesMapping';
import { DeleteCard, Loading, ConfirmationModal } from '../shared';
import { useTranslation } from 'next-i18next';
import { useEffect, useState } from 'react';
import { defaultHeaders, fetcher } from '../utils';
import { PageHeader } from '../shared';
import { BrandingForm } from '../branding';

export const EditIdentityFederationApp = ({
  urls,
  onError,
  onUpdate,
  onDelete,
  excludeFields,
}: {
  urls: { getApp: string; updateApp: string; deleteApp: string; jacksonUrl: string };
  onUpdate?: (data: IdentityFederationApp) => void;
  onError?: (error: Error) => void;
  onDelete?: () => void;
  excludeFields?: 'product'[];
}) => {
  const { t } = useTranslation('common');
  const [delModalVisible, setDelModalVisible] = useState(false);

  const { data, isLoading, error, mutate } = useSWR<{ data: IdentityFederationApp }>(urls.getApp, fetcher);

  useEffect(() => {
    if (error) {
      onError?.(error);
    }
  }, [error, onError]);

  if (isLoading) {
    return <Loading />;
  }

  if (error) {
    return;
  }

  if (!data) {
    return null;
  }

  const app = data?.data;

  const connectionIsOIDC = app.type === 'oidc';
  const connectionIsSAML = !connectionIsOIDC;

  const deleteApp = async () => {
    try {
      await fetch(urls.deleteApp, { method: 'DELETE', headers: defaultHeaders });
      setDelModalVisible(false);
      onDelete?.();
    } catch (err: any) {
      onError?.(err);
    }
  };

  return (
    <>
      <PageHeader title={t('bui-fs-edit-app')} />
      <div className='flex flex-col gap-6'>
        <Edit
          app={app}
          urls={{ patch: urls.updateApp, jacksonUrl: urls.jacksonUrl }}
          onError={onError}
          onUpdate={(data) => {
            mutate({ data });
            onUpdate?.(data);
          }}
          excludeFields={excludeFields}
        />
        {connectionIsSAML && (
          <EditAttributesMapping
            app={app}
            urls={{ patch: urls.updateApp }}
            onError={onError}
            onUpdate={(data) => {
              mutate({ data });
              onUpdate?.(data);
            }}
          />
        )}
        <BrandingForm
          defaults={{
            primaryColor: app.primaryColor,
            logoUrl: app.logoUrl,
            faviconUrl: app.faviconUrl,
          }}
          urls={{ patch: urls.updateApp }}
          onUpdate={(data) => {
            mutate({ data } as { data: IdentityFederationApp });
            onUpdate?.(data as IdentityFederationApp);
          }}
          onError={onError}
          title={t('bui-fs-branding-title')}
          description={t('bui-fs-branding-desc')}
          hideFields={{ companyName: true }}
          federatedAppId={app.id}
        />
        <DeleteCard
          title={t('bui-fs-delete-app-title')}
          description={t('bui-fs-delete-app-desc')}
          buttonLabel={t('bui-shared-delete')}
          onClick={() => setDelModalVisible(true)}
        />
        <ConfirmationModal
          title={t('bui-fs-delete-app-title')}
          description={t('bui-fs-delete-app-desc')}
          visible={delModalVisible}
          onConfirm={() => deleteApp()}
          onCancel={() => setDelModalVisible(false)}
        />
      </div>
    </>
  );
};
