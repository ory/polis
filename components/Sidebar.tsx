import HomeIcon from '@heroicons/react/24/outline/HomeIcon';
import Image from 'next/image';
import Link from 'next/link';
import classNames from 'classnames';
import { useRouter } from 'next/router';

import Logo from '../public/logo.svg';
import { useTranslation } from 'next-i18next';
import SSOLogo from '@components/logo/SSO';
import DSyncLogo from '@components/logo/DSync';
import Cog8ToothIcon from '@heroicons/react/24/outline/Cog8ToothIcon';

type SidebarProps = {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
  branding: any;
  hideIdentityFederation: boolean;
  hideDirectorySync: boolean;
};

type MenuItem = {
  href: string;
  text: string;
  active: boolean;
  icon?: any;
  items?: MenuItem[];
};

export const Sidebar = ({
  isOpen,
  setIsOpen,
  branding,
  hideIdentityFederation,
  hideDirectorySync,
}: SidebarProps) => {
  const { t } = useTranslation('common');
  const { asPath } = useRouter();

  let menus = [
    {
      href: '/admin/dashboard',
      text: t('dashboard'),
      icon: HomeIcon,
      active: asPath.includes('/admin/dashboard'),
    },
    {
      href: '/admin/sso-connection',
      text: t('enterprise_sso'),
      icon: SSOLogo,
      active: asPath.includes('/admin/sso-connection'),
      items: [
        {
          href: '/admin/sso-connection',
          text: t('connections'),
          active:
            asPath.includes('/admin/sso-connection') && !asPath.includes('/admin/sso-connection/setup-link'),
        },
        {
          href: '/admin/sso-connection/setup-link',
          text: t('setup_links'),
          active: asPath.includes('/admin/sso-connection/setup-link'),
        },
        {
          href: '/admin/sso-traces',
          text: t('bui-traces-title'),
          active: asPath.includes('/admin/sso-traces'),
        },
      ],
    },
    {
      hide: 'identityFederation',
      href: '/admin/identity-federation',
      text: t('identity_federation'),
      icon: SSOLogo,
      active: asPath.includes('/admin/identity-federation'),
      items: [
        {
          href: '/admin/identity-federation',
          text: t('apps'),
          active: asPath.includes('/admin/identity-federation'),
        },
      ],
    },
    {
      hide: 'directorySync',
      href: '/admin/directory-sync',
      text: t('directory_sync'),
      icon: DSyncLogo,
      active: asPath.includes('/admin/directory-sync'),
      items: [
        {
          href: '/admin/directory-sync',
          text: t('connections'),
          active:
            asPath.includes('/admin/directory-sync') && !asPath.includes('/admin/directory-sync/setup-link'),
        },
        {
          href: '/admin/directory-sync/setup-link',
          text: t('setup_links'),
          active: asPath.includes('/admin/directory-sync/setup-link'),
        },
      ],
    },
    {
      href: '/admin/settings',
      text: t('settings'),
      icon: Cog8ToothIcon,
      active: asPath.includes('/admin/settings'),
      items: [
        {
          href: '/admin/settings/sso-connection',
          text: 'Single Sign-On',
          active: asPath.includes('/admin/settings/sso-connection'),
        },
        {
          href: '/admin/settings/branding',
          text: 'Branding',
          active: asPath.includes('/admin/settings/branding'),
        },
      ],
    },
  ];

  menus = menus.filter(
    (menu) =>
      !(menu.hide === 'identityFederation' && hideIdentityFederation) &&
      !(menu.hide === 'directorySync' && hideDirectorySync)
  );

  return (
    <>
      {/* Sidebar for mobile */}
      <div
        className={classNames('relative z-40 md:hidden', { hidden: isOpen })}
        role='dialog'
        aria-modal='true'>
        <div className='fixed inset-0 bg-gray-600 bg-opacity-75' />
        <div className='fixed inset-0 z-40 flex'>
          <div className='relative flex w-full max-w-xs flex-1 flex-col bg-white pt-5 pb-4'>
            <div className='absolute top-0 right-0 -mr-12 pt-2'>
              <button
                onClick={() => {
                  setIsOpen(!isOpen);
                }}
                type='button'
                className='ml-1 flex h-10 w-10 items-center justify-center rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white'>
                <span className='sr-only'>{t('close_sidebar')}</span>
                <svg
                  className='h-6 w-6 text-white'
                  xmlns='http://www.w3.org/2000/svg'
                  fill='none'
                  viewBox='0 0 24 24'
                  strokeWidth={2}
                  stroke='currentColor'
                  aria-hidden='true'>
                  <path strokeLinecap='round' strokeLinejoin='round' d='M6 18L18 6M6 6l12 12' />
                </svg>
              </button>
            </div>
            <div className='flex flex-shrink-0 items-center px-4'>
              <BrandingLink t={t} branding={branding}></BrandingLink>
            </div>
            <div className='mt-5 h-0 flex-1 overflow-y-auto'>
              <MenuItems menus={menus} />
            </div>
          </div>
          <div className='w-14 flex-shrink-0' aria-hidden='true'></div>
        </div>
      </div>

      {/* Sidebar for desktop */}
      <div className='hidden md:fixed md:inset-y-0 md:flex md:w-64 md:flex-col'>
        <div className='flex flex-grow flex-col overflow-y-auto border-r border-gray-200 bg-white pt-5'>
          <div className='flex flex-shrink-0 items-center px-4'>
            <BrandingLink t={t} branding={branding}></BrandingLink>
          </div>
          <div className='mt-5 flex flex-1 flex-col'>
            <MenuItems menus={menus} />
          </div>
        </div>
      </div>
    </>
  );
};

const MenuItems = ({ menus }: { menus: MenuItem[] }) => {
  return (
    <nav className='space-y-1'>
      {menus.map((menu, id) => {
        return (
          <div key={id}>
            <ItemLink key={id} {...menu} />
            {menu.items && <SubMenuItems items={menu.items} />}
          </div>
        );
      })}
    </nav>
  );
};

const SubMenuItems = ({ items }: { items: MenuItem[] }) => {
  return (
    <nav className='flex-1 pl-10'>
      <div className='mt-1 space-y-1 border-l-2 border-gray-200'>
        {items.map((item, id) => (
          <ItemLink key={id} {...item} />
        ))}
      </div>
    </nav>
  );
};

const ItemLink = (props: MenuItem) => {
  const { href, text, active } = props;

  return (
    <Link
      href={href}
      className={classNames(
        'group mx-2 flex items-center rounded-md py-2 px-2 text-sm text-gray-900',
        active ? 'bg-gray-100 font-bold' : 'font-medium hover:bg-gray-100 hover:text-gray-900'
      )}>
      {props.icon && <props.icon className='mr-2 h-6 w-6 flex-shrink-0' aria-hidden='true' />}
      {text}
    </Link>
  );
};

const BrandingLink = ({ t, branding }) => {
  return (
    <Link href='/' className='flex items-center'>
      {!branding && (
        <>
          <svg
            className='w-10 h-10 text-gray-200 dark:text-gray-600'
            aria-hidden='true'
            xmlns='http://www.w3.org/2000/svg'
            fill='currentColor'
            viewBox='0 0 20 18'>
            <path d='M18 0H2a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2Zm-5.5 4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3Zm4.376 10.481A1 1 0 0 1 16 15H4a1 1 0 0 1-.895-1.447l3.5-7A1 1 0 0 1 7.468 6a.965.965 0 0 1 .9.5l2.775 4.757 1.546-1.887a1 1 0 0 1 1.618.1l2.541 4a1 1 0 0 1 .028 1.011Z' />
          </svg>
          <div className='w-full ml-2'>
            <div className='h-2.5 bg-gray-200 rounded-full dark:bg-gray-700 w-48'></div>
          </div>
        </>
      )}
      {branding && (
        <>
          <Image
            src={branding ? branding.logoUrl : Logo}
            alt={branding ? branding.companyName : 'Ory Polis'}
            width={32}
            height={32}
            className='h-8 w-auto'
          />
          <span className='ml-4 text-lg font-bold text-gray-900'>
            {(branding ? branding.companyName : 'Ory Polis') + ' ' + t('admin_portal')}
          </span>
        </>
      )}
    </Link>
  );
};
