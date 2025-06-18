import Link from 'next/link';
import { useState } from 'react';
import { useTranslation } from 'next-i18next';
import ArrowTopRightOnSquareIcon from '@heroicons/react/20/solid/ArrowTopRightOnSquareIcon';

export const WellKnownURLs = ({
  jacksonUrl,
  hideIdentityFederation = false,
}: {
  jacksonUrl?: string;
  hideIdentityFederation: boolean;
}) => {
  const { t } = useTranslation('common');
  const [view, setView] = useState<'idp-config' | 'auth' | 'identity-fed'>('idp-config');

  const viewText = t('bui-shared-view');
  const downloadText = t('bui-wku-download');
  const baseUrl = jacksonUrl ?? '';

  const links = [
    {
      title: t('bui-wku-sp-metadata'),
      description: t('bui-wku-sp-metadata-desc'),
      href: `${baseUrl}/.well-known/sp-metadata`,
      buttonText: viewText,
      type: 'idp-config',
    },
    {
      title: t('bui-shared-saml-configuration'),
      description: t('bui-wku-sp-config-desc'),
      href: `${baseUrl}/.well-known/saml-configuration`,
      buttonText: viewText,
      type: 'idp-config',
    },
    {
      title: t('bui-wku-saml-public-cert'),
      description: t('bui-wku-saml-public-cert-desc'),
      href: `${baseUrl}/.well-known/saml.cer`,
      buttonText: downloadText,
      type: 'idp-config',
    },
    {
      title: t('bui-wku-oidc-configuration'),
      description: t('bui-wku-oidc-config-desc'),
      href: `${baseUrl}/.well-known/oidc-configuration`,
      buttonText: viewText,
      type: 'idp-config',
    },
    {
      title: t('bui-wku-oidc-discovery'),
      description: t('bui-wku-oidc-discovery-desc'),
      href: `${baseUrl}/.well-known/openid-configuration`,
      buttonText: viewText,
      type: 'auth',
    },
    {
      title: t('bui-wku-saml-idp-metadata'),
      description: t('bui-wku-saml-idp-metadata-desc'),
      href: `${baseUrl}/.well-known/idp-metadata`,
      buttonText: viewText,
      type: 'identity-fed',
    },
    {
      title: t('bui-wku-saml-idp-configuration'),
      description: t('bui-wku-saml-idp-config-desc'),
      href: `${baseUrl}/.well-known/idp-configuration`,
      buttonText: viewText,
      type: 'identity-fed',
    },
    {
      title: t('bui-shared-oidc-federation'),
      description: t('bui-wku-oidc-federation-desc'),
      href: `${baseUrl}/.well-known/openid-configuration`,
      buttonText: viewText,
      type: 'identity-fed',
    },
  ];

  return (
    <>
      <h2 className='text-emphasis text-xl font-semibold leading-5 tracking-wide dark:text-white pb-4'>
        {t('bui-wku-heading')}
      </h2>
      <div className='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6'>
        <Tab
          isActive={view === 'idp-config'}
          setIsActive={() => setView('idp-config')}
          title={t('bui-wku-idp-configuration-links')}
          description={t('bui-wku-desc-idp-configuration')}
          label={t('bui-wku-idp-configuration-links')}
        />
        <Tab
          isActive={view === 'auth'}
          setIsActive={() => setView('auth')}
          title={t('bui-wku-auth-integration-links')}
          description={t('bui-wku-desc-auth-integration')}
          label={t('bui-wku-auth-integration-links')}
        />
        {hideIdentityFederation ? null : (
          <Tab
            isActive={view === 'identity-fed'}
            setIsActive={() => setView('identity-fed')}
            title={t('bui-wku-identity-federation-links')}
            description={t('bui-wku-desc-identity-federation')}
            label={t('bui-wku-identity-federation-links')}
          />
        )}
      </div>
      <div className='space-y-3 mt-8'>
        {links
          .filter((link) => link.type === view)
          .map((link) => (
            <LinkCard
              key={link.href}
              title={link.title}
              description={link.description}
              href={link.href}
              buttonText={link.buttonText}
            />
          ))}
      </div>
    </>
  );
};

const Tab = ({ isActive, setIsActive, title, description, label }) => {
  return (
    <button
      type='button'
      className={`w-full text-left rounded border hover:border-purple-800 p-4${
        isActive ? ' bg-purple-50 opacity-100' : ' opacity-50'
      }`}
      onClick={setIsActive}
      aria-label={label}>
      <span className='flex flex-col items-end'>
        <span className='font-semibold'>{title}</span>
        <span className='text-sm'>{description}</span>
      </span>
    </button>
  );
};

const LinkCard = ({
  title,
  description,
  href,
  buttonText,
}: {
  title: string;
  description: string;
  href: string;
  buttonText: string;
}) => {
  return (
    <div className='rounded border p-4 hover:border-gray-400'>
      <div className='flex items-center justify-between'>
        <div className='space-y-2'>
          <h3 className='font-bold'>{title}</h3>
          <p className='text-[15px]'>{description}</p>
        </div>
        <div className='mx-4'>
          <Link
            className='btn btn-secondary btn-outline btn-sm w-32'
            href={href}
            target='_blank'
            rel='noreferrer'>
            <ArrowTopRightOnSquareIcon className='w-4 h-4 mr-2' />
            {buttonText}
          </Link>
        </div>
      </div>
    </div>
  );
};
