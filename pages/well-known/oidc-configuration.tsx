import type { NextPage, InferGetStaticPropsType } from 'next';
import React from 'react';
import { useTranslation, Trans } from 'next-i18next';
import jackson from '@lib/jackson';
import { InputWithCopyButton } from '@boxyhq/internal-ui';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { Toaster } from '@components/Toaster';

const SPConfig: NextPage<InferGetStaticPropsType<typeof getServerSideProps>> = ({ oidcRedirectURI }) => {
  const { t } = useTranslation('common');

  return (
    <>
      <Toaster />
      <div className='mt-10 flex w-full justify-center px-5'>
        <div className='w-full rounded border border-gray-200 bg-white p-6 dark:border-gray-700 dark:bg-gray-800 md:w-1/2'>
          <div className='flex flex-col space-y-3'>
            <h2 className='font-bold text-gray-700 md:text-xl'>{t('sp_oidc_config_title')}</h2>
            <p className='text-sm leading-6 text-gray-800'>{t('sp_oidc_config_description')}</p>
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
              <InputWithCopyButton text={oidcRedirectURI} label={t('sp_oidc_redirect_url')} />
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export const getServerSideProps = async ({ locale }) => {
  const { spConfig } = await jackson();

  return {
    props: {
      ...(await serverSideTranslations(locale, ['common'])),
      oidcRedirectURI: spConfig.oidcRedirectURI,
    },
  };
};

export default SPConfig;
