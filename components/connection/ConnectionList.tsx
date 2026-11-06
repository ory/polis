import LinkIcon from '@heroicons/react/24/outline/LinkIcon';
import { useTranslation } from 'next-i18next';
import { useRouter } from 'next/router';
import { ConnectionList } from '@boxyhq/react-ui/sso';
import { InputWithCopyButton, pageLimit, LinkPrimary } from '@boxyhq/internal-ui';

const SSOConnectionList = ({
  setupLinkToken,
  idpEntityID,
  isSettingsView = false,
}: {
  setupLinkToken?: string;
  idpEntityID?: string;
  isSettingsView?: boolean;
}) => {
  const { t } = useTranslation('common');
  const router = useRouter();

  const isSetupLinkView = setupLinkToken ? true : false;
  const getConnectionsUrl = setupLinkToken
    ? `/api/setup/${setupLinkToken}/sso-connection`
    : isSettingsView
      ? '/api/admin/connections?isSystemSSO'
      : '/api/admin/connections';

  const createConnectionUrl = setupLinkToken
    ? `/setup/${setupLinkToken}/sso-connection/new`
    : isSettingsView
      ? '/admin/settings/sso-connection/new'
      : '/admin/sso-connection/new';

  const enablePagination = !isSettingsView && !isSetupLinkView;

  return (
    <div>
      <div className='mb-5 flex items-center justify-between'>
        <h2 className='font-bold text-gray-700 dark:text-white md:text-xl'>
          {isSettingsView ? t('admin_portal_sso') : t('enterprise_sso')}
        </h2>
        <div className='flex gap-2'>
          {!setupLinkToken && !isSettingsView && (
            <LinkPrimary
              Icon={LinkIcon}
              href='/admin/sso-connection/setup-link/new'
              data-testid='create-setup-link'>
              {t('bui-sl-new-link')}
            </LinkPrimary>
          )}
          <LinkPrimary href={createConnectionUrl} data-testid='create-connection'>
            {t('new_connection')}
          </LinkPrimary>
        </div>
      </div>
      {idpEntityID && setupLinkToken && (
        <div className='mb-5 mt-5 items-center justify-between'>
          <div className='form-control'>
            <InputWithCopyButton text={idpEntityID} label={t('idp_entity_id')} />
          </div>
        </div>
      )}

      <ConnectionList
        urls={{
          get: getConnectionsUrl,
        }}
        cols={
          isSetupLinkView
            ? ['provider', 'type', 'status', 'actions']
            : isSettingsView
              ? ['name', 'provider', 'type', 'status', 'actions']
              : undefined
        }
        handleListFetchComplete={(connections) => {
          if (connections?.length === 0 && setupLinkToken) {
            router.replace(`/setup/${setupLinkToken}/sso-connection/new`);
          }
        }}
        paginate={
          enablePagination
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
        handleActionClick={(action: 'edit', payload: any) => {
          const isSystemSSO = payload?.isSystemSSO;
          router.push(
            setupLinkToken
              ? `/setup/${setupLinkToken}/sso-connection/edit/${payload.clientID}`
              : isSettingsView || isSystemSSO
                ? `/admin/settings/sso-connection/edit/${payload.clientID}`
                : `/admin/sso-connection/edit/${payload.clientID}`
          );
        }}
      />
    </div>
  );
};

export default SSOConnectionList;
