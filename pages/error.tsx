import { useTranslation } from 'next-i18next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { GetServerSidePropsContext } from 'next';
import { getErrorMessageFromCookie } from '@lib/utils';

export default function Error({ error }) {
  const { t } = useTranslation('common');

  if (!error.statusCode) {
    return null;
  }

  return (
    <div className='flex h-screen'>
      <div className='m-auto'>
        <section className='bg-white dark:bg-gray-900'>
          <div className='mx-auto max-w-screen-xl py-8 px-4 lg:py-16 lg:px-6'>
            <div className='mx-auto max-w-screen-sm text-center'>
              <h1 className='mb-4 text-7xl font-extrabold tracking-tight text-primary lg:text-9xl'>
                {error.statusCode}
              </h1>
              <p className='mb-4 text-3xl font-bold tracking-tight text-gray-900 dark:text-white md:text-4xl'>
                {t(error.statusText)}
              </p>
              <p className='mb-4 text-lg font-light'>
                {t('sso_error')}: {error.message}
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

export async function getServerSideProps({ locale, req }: GetServerSidePropsContext) {
  const error = getErrorMessageFromCookie(req.cookies.polis_error);

  return {
    props: {
      error,
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}
