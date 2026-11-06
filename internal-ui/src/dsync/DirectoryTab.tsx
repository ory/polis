import classNames from 'classnames';
import { useTranslation } from 'next-i18next';
import { useContext } from 'react';
import { BUIContext } from '../provider';

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const allTabs = ['directory', 'users', 'groups', 'events'] as const;
export type Tabs = (typeof allTabs)[number];

export const DirectoryTab = ({ activeTab, baseUrl }: { activeTab: Tabs; baseUrl: string }) => {
  const { t } = useTranslation('common');
  const { router } = useContext(BUIContext);

  const menus = [
    {
      name: t('bui-dsync-directory'),
      href: baseUrl,
      active: activeTab === 'directory',
    },
    {
      name: t('bui-dsync-users'),
      href: `${baseUrl}/users`,
      active: activeTab === 'users',
    },
    {
      name: t('bui-dsync-groups'),
      href: `${baseUrl}/groups`,
      active: activeTab === 'groups',
    },
    {
      name: t('bui-dsync-webhook-events'),
      href: `${baseUrl}/events`,
      active: activeTab === 'events',
    },
  ];

  return (
    <div className='pb-3'>
      <ul className='-mb-px flex space-x-5 border-b' aria-label='Tabs'>
        {menus.map((menu) => {
          return (
            <li
              onClick={() => router?.push(menu.href)}
              key={menu.href}
              className={classNames(
                'cursor-pointer inline-flex items-center border-b-2 py-4 text-sm font-medium',
                menu.active
                  ? 'border-gray-700 text-gray-700'
                  : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
              )}>
              {menu.name}
            </li>
          );
        })}
      </ul>
    </div>
  );
};
