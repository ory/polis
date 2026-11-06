import { useState } from 'react';
import { useFormik } from 'formik';
import { Button } from 'rsc-daisyui';
import { useTranslation } from 'next-i18next';

import { Card } from '../shared';
import type { SetupLink } from '../types';
import { defaultHeaders } from '../utils';
import { SetupLinkInfo } from './SetupLinkInfo';

interface CreateSetupLinkInput {
  name: string;
  description: string;
  tenant: string;
  product: string;
  expiryDays: number;
  service: 'sso';
  regenerate: boolean;
  redirectUrl: string;
  defaultRedirectUrl: string;
}

export const SSOForm = ({
  urls,
  expiryDays,
  onCreate,
  onError,
  excludeFields,
}: {
  urls: { createLink: string };
  expiryDays: number;
  onCreate: (data: SetupLink) => void;
  onError: (error: Error) => void;
  excludeFields?: 'product'[];
}) => {
  const { t } = useTranslation('common');
  const [setupLink, setSetupLink] = useState<SetupLink | null>(null);

  const formik = useFormik<CreateSetupLinkInput>({
    initialValues: {
      name: '',
      description: '',
      tenant: '',
      product: '',
      expiryDays,
      service: 'sso',
      regenerate: false,
      redirectUrl: '',
      defaultRedirectUrl: '',
    },
    onSubmit: async (values) => {
      const redirectUrlList = values.redirectUrl.split(/\r\n|\r|\n/);

      const rawResponse = await fetch(urls.createLink, {
        method: 'POST',
        body: JSON.stringify({ ...values, redirectUrl: JSON.stringify(redirectUrlList) }),
        headers: defaultHeaders,
      });

      const response = await rawResponse.json();

      if (rawResponse.ok) {
        onCreate(response.data);
        formik.resetForm();
        setSetupLink(response.data);
      } else {
        onError(response.error);
      }
    },
  });

  return (
    <>
      {setupLink && <SetupLinkInfo setupLink={setupLink} onClose={() => setSetupLink(null)} />}
      <form onSubmit={formik.handleSubmit} method='POST'>
        <Card>
          <Card.Body>
            <Card.Description>{t('bui-sl-sso-desc')}</Card.Description>
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-sl-name')}</span>
              </div>
              <input
                type='text'
                placeholder={t('bui-sl-sso-name-placeholder')!}
                className='input input-bordered w-full text-sm'
                name='name'
                onChange={formik.handleChange}
                value={formik.values.name}
              />
            </label>
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-sl-sso-description')}</span>
              </div>
              <input
                type='text'
                className='input input-bordered w-full text-sm'
                name='description'
                onChange={formik.handleChange}
                value={formik.values.description}
              />
            </label>
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-shared-tenant')}</span>
              </div>
              <input
                type='text'
                placeholder='acme'
                className='input input-bordered w-full text-sm'
                name='tenant'
                required
                onChange={formik.handleChange}
                value={formik.values.tenant}
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
                  required
                  onChange={formik.handleChange}
                  value={formik.values.product}
                />
              </label>
            )}
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-sl-allowed-redirect-urls')}</span>
              </div>
              <textarea
                name='redirectUrl'
                placeholder='http://localhost:3366'
                className='textarea-bordered textarea whitespace-pre rounded'
                required
                onChange={formik.handleChange}
                value={formik.values.redirectUrl}
              />
            </label>
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-sl-default-redirect-url')}</span>
              </div>
              <input
                type='url'
                placeholder='http://localhost:3366/login/saml'
                className='input input-bordered w-full text-sm'
                name='defaultRedirectUrl'
                required
                onChange={formik.handleChange}
                value={formik.values.defaultRedirectUrl}
              />
            </label>
            <label className='form-control w-full'>
              <div className='label'>
                <span className='label-text'>{t('bui-sl-expiry-days')}</span>
              </div>
              <input
                type='number'
                placeholder='7'
                className='input input-bordered w-full text-sm'
                name='expiryDays'
                required
                min={1}
                onChange={formik.handleChange}
                value={formik.values.expiryDays}
              />
            </label>
          </Card.Body>
          <Card.Footer>
            <Button
              type='submit'
              className='btn btn-primary btn-md'
              animation={formik.isSubmitting}
              disabled={!formik.dirty || !formik.isValid}>
              {t('bui-sl-create-link')}
            </Button>
          </Card.Footer>
        </Card>
      </form>
    </>
  );
};
