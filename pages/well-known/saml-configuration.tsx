import type { NextPage, InferGetStaticPropsType } from 'next';
import Link from 'next/link';
import React from 'react';
import { useTranslation, Trans } from 'next-i18next';
import jackson from '@lib/jackson';
import { InputWithCopyButton } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { Toaster } from '@components/Toaster';

const SPConfig: NextPage<InferGetStaticPropsType<typeof getServerSideProps>> = ({ config }) => {
  const { t } = useTranslation('common');

  return (
    <>
      <Toaster />
      <div className='mt-10 flex w-full justify-center px-5'>
        <div className='w-full rounded border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800 md:w-1/2'>
          <div className='flex flex-col space-y-3'>
            <h2 className='font-bold text-gray-700 md:text-xl'>{t('sp_saml_config_title')}</h2>
            <p className='text-sm leading-6 text-gray-800'>{t('sp_saml_config_description')}</p>
            <p className='text-sm leading-6 text-gray-600'>
              <Trans
                i18nKey='refer_to_provider_instructions'
                t={t}
                components={{
                  guideLink: (
                    <a
                      href='https://www.ory.sh/docs/polis/sso-providers'
                      target='_blank'
                      rel='noreferrer'
                      className='underline underline-offset-4'>
                      {t('guides')}
                    </a>
                  ),
                }}
              />
            </p>
          </div>
          <div className='mt-6 flex flex-col gap-6'>
            <div className='form-control w-full'>
              <InputWithCopyButton text={config.acsUrl} label={t('sp_acs_url')} />
            </div>
            <div className='form-control w-full'>
              <InputWithCopyButton text={config.entityId} label={t('sp_entity_id')} />
            </div>
            <div className='form-control w-full'>
              <div className='flex flex-col'>
                <label className='mb-2 block text-sm font-medium text-gray-900 dark:text-gray-300'>
                  {t('bui-traces-response')}
                </label>
                <p className='text-sm'>{config.response}</p>
              </div>
            </div>
            <div className='form-control w-full'>
              <div className='flex flex-col'>
                <label className='mb-2 block text-sm font-medium text-gray-900 dark:text-gray-300'>
                  {t('assertion_signature')}
                </label>
                <p className='text-sm'>{config.assertionSignature}</p>
              </div>
            </div>
            <div className='form-control w-full'>
              <div className='flex flex-col'>
                <label className='mb-2 block text-sm font-medium text-gray-900 dark:text-gray-300'>
                  {t('signature_algorithm')}
                </label>
                <p className='text-sm'>{config.signatureAlgorithm}</p>
              </div>
            </div>
            <div className='form-control w-full'>
              <div className='flex flex-col'>
                <label className='mb-2 block text-sm font-medium text-gray-900 dark:text-gray-300'>
                  {t('assertion_encryption')}
                </label>
                <p className='text-sm'>
                  <Trans
                    i18nKey='sp_download_our_public_cert'
                    t={t}
                    components={{
                      downloadLink: (
                        <Link
                          href='/.well-known/saml.cer'
                          className='underline underline-offset-4'
                          target='_blank'>
                          {t('bui-wku-download')}
                        </Link>
                      ),
                    }}
                  />
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export const getServerSideProps = async ({ locale, query }) => {
  const { spConfig } = await jackson();
  const { entityId } = query as { entityId?: string };

  const config = await spConfig.get();
  if (entityId) {
    config.entityId = entityId;
  }

  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
      config,
    },
  };
};

export default SPConfig;
