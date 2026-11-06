import { Button } from 'rsc-daisyui';
import { useTranslation } from 'next-i18next';
import type { IdentityFederationApp } from '../types';
import { useFormik } from 'formik';
import { defaultHeaders } from '../utils';
import { Card } from '../shared';
import { AttributesMapping } from './AttributesMapping';

type Mappings = Pick<IdentityFederationApp, 'mappings'>;

export const EditAttributesMapping = ({
  app,
  urls,
  onUpdate,
  onError,
}: {
  app: IdentityFederationApp;
  urls: { patch: string };
  onUpdate?: (data: IdentityFederationApp) => void;
  onError?: (error: Error) => void;
}) => {
  const { t } = useTranslation('common');

  const formik = useFormik<Mappings>({
    initialValues: {
      mappings: app.mappings || [],
    },
    enableReinitialize: true,
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
    <form onSubmit={formik.handleSubmit} method='POST'>
      <Card>
        <Card.Body>
          <Card.Header>
            <Card.Title>{t('bui-fs-attribute-mappings')}</Card.Title>
            <Card.Description>{t('bui-fs-attribute-mappings-desc')}</Card.Description>
          </Card.Header>
          <AttributesMapping
            mappings={formik.values.mappings || []}
            onAttributeMappingsChange={(newAttributeMappings) => {
              formik.setFieldValue('mappings', newAttributeMappings);
            }}
          />
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
  );
};
