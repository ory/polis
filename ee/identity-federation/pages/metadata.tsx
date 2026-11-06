import Link from 'next/link';
import { useTranslation } from 'next-i18next';
import type { IdentityFederationAppWithMetadata } from '@boxyhq/saml-jackson';
import { Toaster } from '@components/Toaster';
import { InputWithCopyButton, CopyToClipboardButton, LinkOutline } from '@boxyhq/internal-ui';
import LicenseRequired from '@components/LicenseRequired';

type MetadataProps = {
  metadata: Pick<IdentityFederationAppWithMetadata, 'metadata'>['metadata'];
  hasValidLicense: boolean;
};

const Metadata = ({ metadata, hasValidLicense }: MetadataProps) => {
  const { t } = useTranslation('common');

  if (!hasValidLicense) {
    return (
      <div className='p-10'>
        <LicenseRequired />
      </div>
    );
  }

  return (
    <>
      <Toaster />
      <div className='mt-10 flex w-full justify-center px-5'>
        <div className='w-full rounded border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800 md:w-1/2'>
          <h2 className='mb-5 font-bold text-gray-700 md:text-xl'>{t('saml_federation_app_info')}</h2>
          <div className='flex flex-col'>
            <div className='space-y-3'>
              <p className='text-sm leading-6 text-gray-800'>{t('saml_federation_app_info_details')}</p>
              <div className='flex flex-row gap-5'>
                <LinkOutline href={`/.well-known/idp-metadata?download=true`}>
                  <svg
                    className='mr-1 inline-block h-6 w-6'
                    fill='none'
                    viewBox='0 0 24 24'
                    stroke='currentColor'
                    aria-hidden
                    strokeWidth='2'>
                    <path
                      strokeLinecap='round'
                      strokeLinejoin='round'
                      d='M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4'
                    />
                  </svg>
                  {t('download_metadata')}
                </LinkOutline>
                <LinkOutline href={`/.well-known/idp-metadata`} target='_blank'>
                  {t('metadata_url')}
                </LinkOutline>
              </div>
            </div>
            <div className='divider'>OR</div>
            <div className='space-y-6'>
              <div className='form-control w-full'>
                <InputWithCopyButton text={metadata.ssoUrl} label={t('sso_url')} />
              </div>
              <div className='form-control w-full'>
                <InputWithCopyButton text={metadata.entityId} label={t('bui-fs-entity-id')} />
              </div>
              <div className='form-control w-full'>
                <label className='label'>
                  <div className='flex w-full items-center justify-between'>
                    <span className='label-text font-bold'>{t('x509_certificate')}</span>
                    <span className='flex gap-2'>
                      <Link
                        href='/.well-known/saml.cer'
                        target='_blank'
                        className='label-text font-bold text-gray-500 hover:link-primary'>
                        {t('bui-wku-download')}
                      </Link>
                      <CopyToClipboardButton text={metadata.x509cert.trim()} />
                    </span>
                  </div>
                </label>
                <textarea
                  className='textarea-bordered textarea w-full'
                  rows={10}
                  defaultValue={metadata.x509cert.trim()}
                  readOnly></textarea>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Metadata;
