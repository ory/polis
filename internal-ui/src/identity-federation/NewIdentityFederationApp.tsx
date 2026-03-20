import { useFormik } from 'formik';
import TagsInput from 'react-tagsinput';
import { Card, Button } from 'rsc-daisyui';
import { useTranslation } from 'next-i18next';
import type { IdentityFederationApp } from '../types';
import QuestionMarkCircleIcon from '@heroicons/react/24/outline/QuestionMarkCircleIcon';
import { defaultHeaders } from '../utils';
import { AttributesMapping } from './AttributesMapping';
import { PageHeader } from '../shared';
import { ItemList } from '@boxyhq/react-ui/shared';

type NewIdentityFederationAppType = Pick<
  IdentityFederationApp,
  'name' | 'tenant' | 'product' | 'acsUrl' | 'entityId' | 'tenants' | 'mappings' | 'type' | 'redirectUrl'
>;

export const NewIdentityFederationApp = ({
  samlAudience = 'https://saml.boxyhq.com',
  urls,
  onSuccess,
  onError,
  onEntityIdGenerated,
  excludeFields,
}: {
  samlAudience?: string;
  urls: { createApp: string };
  onSuccess?: (data: IdentityFederationApp) => void;
  onError?: (error: Error) => void;
  onEntityIdGenerated?: (entityId: string) => void;
  excludeFields?: 'product'[];
}) => {
  const { t } = useTranslation('common');

  const initialValues: NewIdentityFederationAppType = {
    type: 'saml',
    name: '',
    tenant: '',
    product: '',
    acsUrl: '',
    entityId: '',
    tenants: [],
    mappings: [],
  };

  if (excludeFields) {
    excludeFields.forEach((key) => {
      delete initialValues[key as keyof NewIdentityFederationAppType];
    });
  }

  const formik = useFormik<NewIdentityFederationAppType>({
    initialValues: initialValues,
    onSubmit: async (values) => {
      const rawResponse = await fetch(urls.createApp, {
        method: 'POST',
        body: JSON.stringify(values),
        headers: defaultHeaders,
      });

      const response = await rawResponse.json();

      if (rawResponse.ok) {
        onSuccess?.(response.data);
      } else {
        onError?.(response.error);
      }
    },
  });

  const connectionIsOIDC = formik.values.type === 'oidc';
  const connectionIsSAML = !connectionIsOIDC;

  const generateEntityId = () => {
    const id = crypto.randomUUID().replace(/-/g, '');
    const entityId = `${samlAudience}/${id}`;
    formik.setFieldValue('entityId', entityId);
    navigator.clipboard.writeText(entityId);
    onEntityIdGenerated?.(entityId);
  };

  return (
    <>
      <PageHeader title={t('bui-fs-create-app')} />
      <form onSubmit={formik.handleSubmit} method='POST'>
        <Card className='p-6 rounded space-y-3'>
          <div className='mb-4 flex items-center'>
            <div className='mr-2 py-3'>{t('bui-fs-select-app-type')}:</div>
            <div className='flex w-52'>
              <div className='form-control'>
                <label className='label mr-4 cursor-pointer'>
                  <input
                    type='radio'
                    name='type'
                    value='saml'
                    className='radio-primary radio'
                    checked={formik.values.type === 'saml'}
                    onChange={formik.handleChange}
                  />
                  <span className='label-text ml-1'>{t('bui-fs-saml')}</span>
                </label>
              </div>
              <div className='form-control'>
                <label className='label mr-4 cursor-pointer' data-testid='sso-type-oidc'>
                  <input
                    type='radio'
                    name='type'
                    value='oidc'
                    className='radio-primary radio'
                    checked={formik.values.type === 'oidc'}
                    onChange={formik.handleChange}
                  />
                  <span className='label-text ml-1'>{t('bui-shared-oidc')}</span>
                </label>
              </div>
            </div>
          </div>

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
              placeholder='example.com'
              className='input input-bordered w-full text-sm'
              name='tenant'
              value={formik.values.tenant}
              onChange={formik.handleChange}
              required
            />
          </label>
          {!excludeFields?.includes('product') && (
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-shared-product')}</span>
              </div>
              <input
                type='text'
                placeholder='MyApp'
                className='input input-bordered w-full text-sm'
                name='product'
                value={formik.values.product}
                onChange={formik.handleChange}
                required
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
          {connectionIsSAML && (
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-fs-entity-id')}</span>
                <span className='label-text-alt'>
                  <div className='flex items-center gap-1'>
                    <span
                      className='cursor-pointer border-stone-600 border p-1 rounded'
                      onClick={generateEntityId}>
                      {t('bui-fs-generate-sp-entity-id')}
                    </span>
                    <div className='tooltip tooltip-left' data-tip={t('bui-fs-entity-id-instruction')}>
                      <QuestionMarkCircleIcon className='h-5 w-5' />
                    </div>
                  </div>
                </span>
              </div>
              <input
                type='text'
                placeholder='https://your-sp.com/saml/entityId'
                className='input input-bordered w-full text-sm'
                name='entityId'
                value={formik.values.entityId}
                onChange={formik.handleChange}
                required
              />
              <label className='label'>
                <span className='label-text-alt'>{t('bui-fs-entity-id-change-restriction')}</span>
              </label>
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
          {connectionIsSAML && (
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-fs-attribute-mappings')}</span>
              </div>
              <div className='label'>
                <span className='label-text-alt'>{t('bui-fs-attribute-mappings-desc')}</span>
              </div>
              <AttributesMapping
                mappings={formik.values.mappings || []}
                onAttributeMappingsChange={(mappings) => formik.setFieldValue('mappings', mappings)}
              />
            </label>
          )}
          <div className='flex gap-2 justify-end pt-6'>
            <Button
              type='submit'
              className='btn btn-primary btn-md'
              animation={formik.isSubmitting}
              disabled={!formik.dirty || !formik.isValid}>
              {t('bui-fs-create-app-btn')}
            </Button>
          </div>
        </Card>
      </form>
    </>
  );
};
