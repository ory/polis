import type { Branding, IdentityFederationApp } from '../types';
import { useTranslation } from 'next-i18next';
import { ButtonPrimary, Card, Error, Loading } from '../shared';
import { useFormik } from 'formik';
import { useFetch, parseResponseContent } from '../hooks';
import { boxyhqBranding } from './index';

export const BrandingForm = ({
  defaults,
  urls,
  onUpdate,
  onError,
  title,
  description,
  hideFields,
  federatedAppId,
}: {
  defaults?: Partial<Branding>;
  urls: { getBranding?: string; patch?: string; post?: string; jacksonUrl?: string };
  onUpdate?: (data: IdentityFederationApp | Branding) => void;
  onError?: (error: Error) => void;
  title?: string;
  description?: string;
  hideFields?: Partial<{ [key in keyof Branding]: boolean }>;
  federatedAppId?: string;
}) => {
  const { t } = useTranslation('common');

  const {
    data,
    isLoading: isLoadingBranding,
    error,
  } = useFetch<{ data: Branding }>({
    url: urls.getBranding,
  });

  const branding = data?.data;

  const formik = useFormik<Branding>({
    initialValues: {
      logoUrl: branding?.logoUrl || `${urls.jacksonUrl ?? ''}${defaults?.logoUrl ?? ''}` || '',
      faviconUrl: branding?.faviconUrl || `${urls.jacksonUrl ?? ''}${defaults?.faviconUrl ?? ''}` || '',
      companyName: branding?.companyName || defaults?.companyName || '',
      primaryColor: branding?.primaryColor || defaults?.primaryColor || boxyhqBranding.primaryColor,
    },
    onSubmit: async (values) => {
      const rawResponse = await fetch(urls.patch ?? urls.post!, {
        method: urls.patch ? 'PATCH' : 'POST',
        body: JSON.stringify({ ...values, id: federatedAppId }),
        headers: {
          'Content-Type': 'application/json',
        },
      });
      const response = await parseResponseContent(rawResponse);

      if (rawResponse.ok) {
        onUpdate?.(response.data);
      } else {
        onError?.(response.error);
      }
    },
    enableReinitialize: true,
  });

  const isFieldEnabled = (field: keyof Branding) => {
    if (hideFields?.[field] === true) {
      return false;
    }
    return true;
  };

  if (isLoadingBranding) {
    return <Loading />;
  }

  if (error) {
    return <Error message={error.message} />;
  }

  return (
    <form onSubmit={formik.handleSubmit}>
      <Card>
        <Card.Body>
          <Card.Header>
            {title && <Card.Title>{title}</Card.Title>}
            {description && <Card.Description>{description}</Card.Description>}
          </Card.Header>
          <div className='flex flex-col'>
            {isFieldEnabled('logoUrl') && (
              <div className='form-control w-full'>
                <label className='label' htmlFor='logoUrl'>
                  <span className='label-text'>{t('bui-branding-logo-url')}</span>
                </label>
                <input
                  type='url'
                  name='logoUrl'
                  id='logoUrl'
                  className='input-bordered input text-sm'
                  onChange={formik.handleChange}
                  value={formik.values.logoUrl}
                  placeholder='https://company.com/logo.png'
                />
                <div className='label'>
                  <span className='label-text-alt'>{t('bui-branding-logo-url-desc')}</span>
                </div>
              </div>
            )}
            {isFieldEnabled('faviconUrl') && (
              <div className='form-control w-full'>
                <label className='label' htmlFor='faviconUrl'>
                  <span className='label-text'>{t('bui-branding-favicon-url')}</span>
                </label>
                <input
                  type='url'
                  name='faviconUrl'
                  id='faviconUrl'
                  className='input-bordered input text-sm'
                  onChange={formik.handleChange}
                  value={formik.values.faviconUrl}
                  placeholder='https://company.com/favicon.ico'
                />
                <div className='label'>
                  <span className='label-text-alt'>{t('bui-branding-favicon-url-desc')}</span>
                </div>
              </div>
            )}
            {isFieldEnabled('companyName') && (
              <div className='form-control w-full'>
                <label className='label' htmlFor='companyName'>
                  <span className='label-text'>{t('bui-branding-company-name')}</span>
                </label>
                <input
                  type='text'
                  name='companyName'
                  id='companyName'
                  className='input-bordered input text-sm'
                  onChange={formik.handleChange}
                  value={formik.values.companyName}
                  placeholder='Acme, Inc.'
                />
                <div className='label'>
                  <span className='label-text-alt'>{t('bui-branding-company-name-desc')}</span>
                </div>
              </div>
            )}
            {isFieldEnabled('primaryColor') && (
              <div className='form-control'>
                <label className='label' htmlFor='primaryColor'>
                  <span className='label-text'>{t('bui-branding-primary-color')}</span>
                </label>
                <input
                  type='color'
                  name='primaryColor'
                  id='primaryColor'
                  onChange={formik.handleChange}
                  value={formik.values.primaryColor}
                />
                <div className='label'>
                  <span className='label-text-alt'>{t('bui-branding-primary-color-desc')}</span>
                </div>
              </div>
            )}
          </div>
        </Card.Body>
        <Card.Footer>
          <ButtonPrimary
            loading={formik.isSubmitting}
            disabled={!formik.dirty || !formik.isValid}
            type='submit'>
            {t('bui-shared-save-changes')}
          </ButtonPrimary>
        </Card.Footer>
      </Card>
    </form>
  );
};
