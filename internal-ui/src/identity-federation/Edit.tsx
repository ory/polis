import { useState } from 'react';
import { Button } from 'rsc-daisyui';
import type { IdentityFederationApp } from '../types';
import TagsInput from 'react-tagsinput';
import { useTranslation } from 'next-i18next';
import { useFormik } from 'formik';
import EyeIcon from '@heroicons/react/24/outline/EyeIcon';
import EyeSlashIcon from '@heroicons/react/24/outline/EyeSlashIcon';

import { Card } from '../shared';
import { defaultHeaders } from '../utils';
import { ItemList } from '@boxyhq/react-ui/shared';
import { CopyToClipboardButton } from '../shared/InputWithCopyButton';
import { IconButton } from '../shared/IconButton';

type EditApp = Pick<IdentityFederationApp, 'name' | 'acsUrl' | 'tenants' | 'redirectUrl'>;

export const Edit = ({
  app,
  urls,
  onError,
  onUpdate,
  excludeFields,
}: {
  app: IdentityFederationApp;
  urls: { patch: string; jacksonUrl: string };
  onUpdate?: (data: IdentityFederationApp) => void;
  onError?: (error: Error) => void;
  excludeFields?: 'product'[];
}) => {
  const { t } = useTranslation('common');
  const [isSecretShown, setisSecretShown] = useState(false);

  const connectionIsOIDC = app.type === 'oidc';
  const connectionIsSAML = !connectionIsOIDC;

  const formik = useFormik<EditApp>({
    enableReinitialize: true,
    initialValues: {
      name: app.name || '',
      acsUrl: app.acsUrl || '',
      tenants: app.tenants || [],
      redirectUrl: app.redirectUrl || [],
    },
    onSubmit: async (values) => {
      const rawResponse = await fetch(urls.patch, {
        method: 'PATCH',
        body: JSON.stringify({ ...values, id: app.id }),
        headers: defaultHeaders,
      });

      const response = await rawResponse.json();

      if (rawResponse.ok) {
        onUpdate?.(response.data);
      } else {
        onError?.(response.error);
      }
    },
  });

  return (
    <>
      <div className='flex flex-col gap-6'>
        <form onSubmit={formik.handleSubmit} method='POST'>
          <Card>
            <Card.Body>
              <div className='flex flex-col space-y-3'>
                <label className='form-control w-full'>
                  <div className='label'>
                    <span className='label-text'>{t('bui-shared-name')}</span>
                  </div>
                  <input
                    type='text'
                    placeholder='Your app'
                    className='input input-bordered w-full text-sm'
                    name='name'
                    value={formik.values.name}
                    onChange={formik.handleChange}
                    required
                  />
                </label>
                <label className='form-control w-full'>
                  <div className='label'>
                    <span className='label-text'>{t('bui-shared-tenant')}</span>
                  </div>
                  <input
                    type='text'
                    className='input input-bordered w-full text-sm bg-gray-100'
                    value={app.tenant}
                    readOnly={true}
                  />
                </label>
                {!excludeFields?.includes('product') && (
                  <label className='form-control w-full'>
                    <div className='label'>
                      <span className='label-text'>{t('bui-shared-product')}</span>
                    </div>
                    <input
                      type='text'
                      className='input input-bordered w-full text-sm bg-gray-100'
                      value={app.product}
                      readOnly={true}
                    />
                  </label>
                )}
                {connectionIsOIDC && (
                  <label className='form-control w-full'>
                    <div className='label'>
                      <span className='label-text'>{t('bui-fs-client-id')}</span>
                      <div className='flex'>
                        <CopyToClipboardButton text={app.clientID!} />
                      </div>
                    </div>
                    <input
                      type='text'
                      className='input-bordered input bg-gray-100'
                      defaultValue={app.clientID}
                      readOnly={true}
                    />
                  </label>
                )}
                {connectionIsOIDC && (
                  <label className='form-control w-full'>
                    <div className='label'>
                      <span className='label-text'>{t('bui-fs-client-secret')}</span>
                      <div className='flex'>
                        <IconButton
                          tooltip={isSecretShown ? t('bui-shared-hide') : t('bui-shared-show')}
                          Icon={isSecretShown ? EyeSlashIcon : EyeIcon}
                          className='hover:text-primary mr-2'
                          onClick={(e) => {
                            e.preventDefault();
                            setisSecretShown(!isSecretShown);
                          }}
                        />
                        <CopyToClipboardButton text={app.clientSecret!} />
                      </div>
                    </div>
                    <input
                      type={isSecretShown ? 'text' : 'password'}
                      className='input-bordered input bg-gray-100'
                      defaultValue={app.clientSecret}
                      readOnly={true}
                    />
                  </label>
                )}
                {connectionIsSAML && (
                  <label className='form-control w-full'>
                    <div className='label'>
                      <span className='label-text'>{t('bui-fs-entity-id')}</span>
                    </div>
                    <input
                      type='text'
                      className='input input-bordered w-full text-sm bg-gray-100'
                      value={app.entityId}
                      readOnly={true}
                    />
                    <label className='label'>
                      <span className='label-text-alt'>{t('bui-fs-entity-id-edit-desc')}</span>
                    </label>
                  </label>
                )}
                {connectionIsSAML && (
                  <label className='form-control w-full'>
                    <div className='label'>
                      <span className='label-text'>{t('bui-fs-initiate-login-uri')}</span>
                      <div className='flex'>
                        <CopyToClipboardButton
                          text={`${urls.jacksonUrl}/api/identity-federation/oidc/idp-login/${app.id}`}
                        />
                      </div>
                    </div>
                    <input
                      type='text'
                      className='input-bordered input bg-gray-100'
                      defaultValue={`${urls.jacksonUrl}/api/identity-federation/oidc/idp-login/${app.id}`}
                      readOnly={true}
                    />
                  </label>
                )}
                {connectionIsSAML && (
                  <label className='form-control w-full'>
                    <div className='label'>
                      <span className='label-text'>{t('bui-shared-acs-url')}</span>
                    </div>
                    <input
                      type='url'
                      placeholder='https://your-sp.com/saml/acs'
                      className='input input-bordered w-full text-sm'
                      name='acsUrl'
                      value={formik.values.acsUrl}
                      onChange={formik.handleChange}
                      required
                    />
                  </label>
                )}
                {connectionIsOIDC && (
                  <label className='form-control w-full'>
                    <ItemList
                      classNames={{ label: 'label', input: 'input input-bordered input-sm w-full' }}
                      label={t('bui-sl-allowed-redirect-urls-new')}
                      inputType={'url'}
                      currentlist={formik.values.redirectUrl || ['']}
                      fieldName='redirectUrl'
                      handleItemListUpdate={(fieldName, newList) => formik.setFieldValue(fieldName, newList)}
                    />
                  </label>
                )}
                <label className='form-control w-full'>
                  <label className='label'>
                    <span className='label-text'>{t('bui-fs-tenants')}</span>
                  </label>
                  <TagsInput
                    value={formik.values.tenants}
                    onChange={(tags: string[]) => formik.setFieldValue('tenants', tags)}
                    onlyUnique={true}
                    inputProps={{
                      placeholder: t('bui-fs-enter-tenant'),
                      autoComplete: 'off',
                    }}
                    focusedClassName='input-focused'
                    addOnBlur={true}
                  />
                  <label className='label'>
                    <span className='label-text-alt'>{t('bui-fs-tenants-mapping-desc')}</span>
                  </label>
                </label>
              </div>
            </Card.Body>
            <Card.Footer>
              <Button
                type='submit'
                className='btn btn-primary btn-md'
                animation={formik.isSubmitting}
                disabled={!formik.dirty || !formik.isValid}>
                {t('bui-shared-save-changes')}
              </Button>
            </Card.Footer>
          </Card>
        </form>
      </div>
    </>
  );
};
