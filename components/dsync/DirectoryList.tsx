import LinkIcon from '@heroicons/react/24/outline/LinkIcon';
import { useTranslation } from 'next-i18next';
import { useRouter } from 'next/router';
import { DirectoryList } from '@boxyhq/react-ui/dsync';
import { pageLimit, LinkPrimary } from '@boxyhq/internal-ui';

const DSyncDirectoryList = ({ setupLinkToken }: { setupLinkToken?: string }) => {
  const { t } = useTranslation('common');
  const router = useRouter();

  const isSetupLinkView = setupLinkToken ? true : false;
  const getDirectoriesUrl = setupLinkToken
    ? `/api/setup/${setupLinkToken}/directory-sync`
    : '/api/admin/directory-sync';
  const createDirectoryUrl = setupLinkToken
    ? `/setup/${setupLinkToken}/directory-sync/new`
    : '/admin/directory-sync/new';

  return (
    <>
      <div className='mb-5 flex items-center justify-between'>
        <h2 className='font-bold text-gray-700 dark:text-white md:text-xl'>{t('directory_sync')}</h2>
        <div className='flex gap-2'>
          {!setupLinkToken && (
            <LinkPrimary Icon={LinkIcon} href='/admin/directory-sync/setup-link/new'>
              {t('bui-sl-new-link')}
            </LinkPrimary>
          )}
          <LinkPrimary href={createDirectoryUrl}>{t('new_directory')}</LinkPrimary>
        </div>
      </div>
      <DirectoryList
        urls={{
          get: getDirectoriesUrl,
        }}
        cols={isSetupLinkView ? ['name', 'type', 'status', 'actions'] : undefined}
        paginate={
          !isSetupLinkView
            ? {
                itemsPerPage: pageLimit,
                handlePageChange: (payload) => {
                  router.push(
                    {
                      pathname: router.pathname,
                      query: {
                        ...router.query,
                        ...payload,
                      },
                    },
                    undefined,
                    { shallow: true }
                  );
                },
              }
            : undefined
        }
        handleActionClick={(action: 'view' | 'edit', directory: any) => {
          if (action === 'view') {
            router.push(
              setupLinkToken
                ? `/setup/${setupLinkToken}/directory-sync/${directory.id}`
                : `/admin/directory-sync/${directory.id}`
            );
          } else if (action === 'edit') {
            router.push(
              setupLinkToken
                ? `/setup/${setupLinkToken}/directory-sync/${directory.id}/edit`
                : `/admin/directory-sync/${directory.id}/edit`
            );
          }
        }}
      />
    </>
  );
};

export default DSyncDirectoryList;
