import { useTranslation } from 'next-i18next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { GetServerSidePropsContext } from 'next';

export default function Error({ error }) {
  const { t } = useTranslation('common');

  const { statusCode, message } = error;
  let statusText = '';
  if (typeof statusCode === 'number') {
    if (statusCode >= 400 && statusCode <= 499) {
      statusText = t('client_error');
    }
    if (statusCode >= 500 && statusCode <= 599) {
      statusText = t('server_error');
    }
  }

  if (statusCode === null) {
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
                {statusText}
              </p>
              <p className='mb-4 text-lg font-light'>
                {t('sso_error')}: {message}
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function getErrorCookie(cookie) {
  const matches = cookie.match(
    new RegExp('(?:^|; )' + 'jackson_error'.replace(/([.$?*|{}()[]\\\/\+^])/g, '\\$1') + '=([^;]*)')
  );
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

export async function getServerSideProps({ locale, req }: GetServerSidePropsContext) {
  const error = {} as { statusCode: number | null; message: string };
  const _error = getErrorCookie(req.headers.cookie || '');
  try {
    const { statusCode, message } = JSON.parse(_error!);
    error.statusCode = statusCode;
    error.message = message;
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (err) {
    console.error('Unknown error format');
  }

  return {
    props: {
      error,
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}
