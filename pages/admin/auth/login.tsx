import { useState, type ReactElement } from 'react';
import type { GetServerSidePropsContext, InferGetServerSidePropsType } from 'next';
import { useRouter } from 'next/router';
import Link from 'next/link';
import Image from 'next/image';
import { useSession, getCsrfToken, signIn, SessionProvider } from 'next-auth/react';
import { useTranslation, Trans } from 'next-i18next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { errorToast, successToast } from '@components/Toaster';
import { ButtonOutline, Loading } from '@boxyhq/internal-ui';
import { Login as SSOLogin } from '@boxyhq/react-ui/sso';
import { adminPortalSSODefaults } from '@lib/env';
import { getPortalBranding } from '@ee/branding/utils';

const Login = ({
  csrfToken,
  tenant,
  product,
  isEmailPasswordEnabled,
  isMagicLinkEnabled,
  branding,
}: InferGetServerSidePropsType<typeof getServerSideProps>) => {
  const { t } = useTranslation('common');
  const router = useRouter();
  const { status } = useSession();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [authMethod, setAuthMethod] = useState('credentials');

  let { callbackUrl } = router.query as { callbackUrl: string };

  callbackUrl = callbackUrl || '/admin/sso-connection';

  if (status === 'loading') {
    return <Loading />;
  }

  if (status === 'authenticated') {
    router.push(callbackUrl);
    return;
  }

  const onSSOSubmit = async ({ ssoIdentifier }) => {
    await signIn('boxyhq-saml', undefined, { client_id: ssoIdentifier });
  };

  // Handle login with email and password
  const onEmailPasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    setLoading(true);
    setAuthMethod('credentials');

    const response = await signIn('credentials', {
      email,
      password,
      redirect: false,
      callbackUrl,
    });

    setLoading(false);

    if (!response) {
      return;
    }

    const { error } = response;

    if (error) {
      errorToast(error);
    }
  };

  // Handle login with magic link
  const onMagicLinkLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) {
      errorToast(t('email_required'));
      return;
    }

    setLoading(true);
    setAuthMethod('email');

    const response = await signIn('email', {
      email,
      csrfToken,
      redirect: false,
    });

    setLoading(false);

    if (!response) {
      return;
    }

    const { error } = response;

    if (error) {
      errorToast(error);
    } else {
      successToast(t('login_success_toast'));
    }
  };

  return (
    <>
      <div className='flex min-h-screen flex-col items-center justify-center'>
        <div className='flex flex-col px-4 sm:mx-auto sm:w-full sm:max-w-[480px]'>
          <div className='mt-4 border px-6 py-8 text-left shadow-md'>
            <div className='space-y-3'>
              <div className='flex justify-center'>
                <Image
                  src={branding ? branding.logoUrl : '/logo.svg'}
                  alt={(branding ? branding.companyName : 'Ory Polis') + ' logo'}
                  width={50}
                  height={50}
                />
              </div>
              <h2 className='text-center text-3xl font-extrabold text-gray-900'>
                {(branding ? branding.companyName : 'Ory Polis') + ' ' + t('admin_portal')}
              </h2>
              <p className='text-center text-sm text-gray-600'>{t('boxyhq_tagline')}</p>
            </div>

            {(isEmailPasswordEnabled || isMagicLinkEnabled) && (
              <form method='POST' onSubmit={onEmailPasswordLogin}>
                <div className='mt-6'>
                  <div className='flex flex-col gap-3'>
                    <label className='block text-sm font-medium'>
                      {t('bui-shared-email')}
                      <input
                        type='email'
                        placeholder={t('bui-shared-email')}
                        className='input-bordered input mt-2 w-full rounded-md'
                        required
                        onChange={(e) => {
                          setEmail(e.target.value);
                        }}
                        value={email}
                      />
                    </label>
                    {isEmailPasswordEnabled && (
                      <>
                        <label className='block text-sm font-medium'>
                          {t('password')}
                          <input
                            type='password'
                            placeholder={t('password')}
                            className='input-bordered input mt-2 w-full rounded-md'
                            required
                            onChange={(e) => {
                              setPassword(e.target.value);
                            }}
                            value={password}
                          />
                        </label>
                        <ButtonOutline
                          loading={loading && authMethod === 'credentials'}
                          className='btn-block'
                          type='submit'>
                          {t('sign_in')}
                        </ButtonOutline>
                      </>
                    )}
                  </div>
                </div>
              </form>
            )}

            {/* No login methods enabled */}
            {!isEmailPasswordEnabled && !isMagicLinkEnabled && (
              <div className='mt-10 text-center font-medium text-gray-600'>
                <Trans
                  i18nKey='learn_to_enable_auth_methods'
                  t={t}
                  components={{
                    docLink: (
                      <a
                        href='https://www.ory.sh/docs/polis/admin-portal'
                        target='_blank'
                        rel='noopener noreferrer'
                        className='underline underline-offset-2'>
                        {t('documentation')}
                      </a>
                    ),
                  }}
                />
              </div>
            )}

            <div className='mt-10 flex flex-col gap-3'>
              {isMagicLinkEnabled && (
                <ButtonOutline
                  loading={loading && authMethod === 'email'}
                  className='btn-block'
                  onClick={onMagicLinkLogin}
                  type='button'>
                  {t('send_magic_link')}
                </ButtonOutline>
              )}
              <SSOLogin
                buttonText={t('login_with_sso')}
                ssoIdentifier={`tenant=${tenant}&product=${product}`}
                onSubmit={onSSOSubmit}
                classNames={{
                  button: 'btn-outline btn-block btn',
                }}
                innerProps={{
                  button: { 'data-testid': 'sso-login-button' },
                }}
              />
            </div>
          </div>
        </div>
        <Link href='/.well-known' className='my-3 text-sm underline underline-offset-4' target='_blank'>
          {t('bui-wku-heading')}
        </Link>
      </div>
    </>
  );
};

Login.getLayout = function getLayout(page: ReactElement) {
  return <SessionProvider>{page}</SessionProvider>;
};

export const getServerSideProps = async (context: GetServerSidePropsContext) => {
  const { locale }: GetServerSidePropsContext = context;

  const isMagicLinkEnabled = process.env.NEXTAUTH_ACL ? true : false;
  const isEmailPasswordEnabled = process.env.NEXTAUTH_ADMIN_CREDENTIALS ? true : false;

  const { tenant, product } = adminPortalSSODefaults;

  const branding = await getPortalBranding();

  return {
    props: {
      csrfToken: await getCsrfToken(context),
      tenant,
      product,
      isMagicLinkEnabled,
      isEmailPasswordEnabled,
      branding,
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
};

export default Login;
