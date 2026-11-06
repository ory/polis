import { useEffect, useState } from 'react';
import { useTranslation } from 'next-i18next';
import EyeIcon from '@heroicons/react/24/outline/EyeIcon';
import TrashIcon from '@heroicons/react/24/outline/TrashIcon';
import ArrowPathIcon from '@heroicons/react/24/outline/ArrowPathIcon';
import ClipboardDocumentIcon from '@heroicons/react/24/outline/ClipboardDocumentIcon';

import { addQueryParamsToPath, copyToClipboard } from '../utils';
import { TableBodyType } from '../shared/Table';
import { pageLimit } from '../shared/Pagination';
import { usePaginate, useRouter, useFetch } from '../hooks';
import type { IdentityFederationApp, SetupLink, SetupLinkService } from '../types';
import {
  Loading,
  Table,
  EmptyState,
  Error,
  Pagination,
  PageHeader,
  ButtonPrimary,
  Badge,
  ConfirmationModal,
} from '../shared';
import { SetupLinkInfoModal } from './SetupLinkInfoModal';

type ExcludeFields = keyof Pick<IdentityFederationApp, 'product'>;

export const SetupLinks = ({
  urls,
  excludeFields,
  actions,
  service,
  onCopy,
  onRegenerate,
  onError,
  onDelete,
}: {
  urls: { getLinks: string; deleteLink: string; regenerateLink: string };
  excludeFields?: ExcludeFields[];
  actions: { newLink: string };
  service: SetupLinkService;
  onCopy: (setupLink: SetupLink) => void;
  onRegenerate: (setupLink: SetupLink) => void;
  onError: (error: Error) => void;
  onDelete: (setupLink: SetupLink) => void;
}) => {
  const { router } = useRouter();
  const { t } = useTranslation('common');
  const [showDelModal, setDelModal] = useState(false);
  const [showSetupLink, setShowSetupLink] = useState(false);
  const [showRegenModal, setShowRegenModal] = useState(false);
  const [setupLink, setSetupLink] = useState<SetupLink | null>(null);
  const { paginate, setPaginate, pageTokenMap, setPageTokenMap } = usePaginate(router!);

  const params = {
    pageOffset: paginate.offset,
    pageLimit: pageLimit,
    service,
  };

  // For DynamoDB
  if (paginate.offset > 0 && pageTokenMap[paginate.offset - pageLimit]) {
    params['pageToken'] = pageTokenMap[paginate.offset - pageLimit];
  }

  const getLinksUrl = addQueryParamsToPath(urls.getLinks, params);
  const { data, isLoading, error, refetch } = useFetch<{ data: SetupLink[]; pageToken?: string }>({
    url: getLinksUrl,
  });

  const nextPageToken = data?.pageToken;

  useEffect(() => {
    if (nextPageToken) {
      setPageTokenMap((tokenMap) => ({ ...tokenMap, [paginate.offset]: nextPageToken }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nextPageToken, paginate.offset]);

  if (isLoading) {
    return <Loading />;
  }

  if (error) {
    return <Error message={error.message} />;
  }

  if (!data) {
    return null;
  }

  const links = data?.data || [];
  const noLinks = links.length === 0 && paginate.offset === 0;
  const noMoreResults = links.length === 0 && paginate.offset > 0;

  let cols = [
    t('bui-shared-tenant'),
    t('bui-shared-product'),
    t('bui-sl-validity'),
    t('bui-shared-status'),
    t('bui-shared-actions'),
  ];

  // Exclude fields
  cols = cols.filter((col) => !excludeFields?.includes(col.toLowerCase() as ExcludeFields));

  const body: TableBodyType[] = links.map((setupLink) => {
    const cells: TableBodyType['cells'] = [
      {
        wrap: true,
        text: setupLink.tenant,
      },
    ];

    if (!excludeFields?.includes('product')) {
      cells.push({
        wrap: true,
        text: setupLink.product,
      });
    }

    cells.push(
      {
        wrap: false,
        text: new Date(setupLink.validTill).toLocaleString(),
      },
      {
        wrap: false,
        element:
          new Date(setupLink.validTill) > new Date() ? (
            <Badge color='primary'>{t('bui-shared-active')}</Badge>
          ) : (
            <Badge color='warning'>{t('bui-sl-expired')}</Badge>
          ),
      },
      {
        actions: [
          {
            text: t('bui-shared-copy'),
            onClick: () => {
              copyToClipboard(setupLink.url);
              onCopy(setupLink);
            },
            icon: <ClipboardDocumentIcon className='h-5 w-5' />,
          },
          {
            text: t('bui-shared-view'),
            onClick: () => {
              setSetupLink(setupLink);
              setShowSetupLink(true);
            },
            icon: <EyeIcon className='h-5 w-5' />,
          },
          {
            text: t('bui-sl-regenerate'),
            onClick: () => {
              setSetupLink(setupLink);
              setShowRegenModal(true);
            },
            icon: <ArrowPathIcon className='h-5 w-5' />,
          },
          {
            destructive: true,
            text: t('bui-shared-delete'),
            onClick: () => {
              setSetupLink(setupLink);
              setDelModal(true);
            },
            icon: <TrashIcon className='h-5 w-5' />,
          },
        ],
      }
    );

    return {
      id: setupLink.setupID,
      cells,
    };
  });

  // Delete setup link
  const deleteSetupLink = async () => {
    if (!setupLink) {
      return;
    }

    const rawResponse = await fetch(
      `${urls.deleteLink}?id=${setupLink.setupID}&service=${setupLink.service}`,
      {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );

    const response = await rawResponse.json();

    if (rawResponse.ok) {
      setDelModal(false);
      setSetupLink(null);
      onDelete(setupLink);
      refetch();
    } else {
      onError(response.error);
    }
  };

  // Regenerate a setup link
  const regenerateSetupLink = async () => {
    if (!setupLink) {
      return;
    }

    const rawResponse = await fetch(urls.regenerateLink, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...setupLink,
        regenerate: true,
      }),
    });

    const response = await rawResponse.json();

    if (rawResponse.ok) {
      onRegenerate(response.data);
      setShowRegenModal(false);
      refetch();
      setSetupLink(response.data);
      setShowSetupLink(true);
    } else {
      onError(response.error);
    }
  };

  return (
    <div className='space-y-3'>
      <PageHeader
        title={service === 'dsync' ? t('bui-sl-dsync-title') : t('bui-sl-sso-title')}
        actions={
          <>
            <ButtonPrimary onClick={() => router?.push(actions.newLink)} className='btn-md'>
              {t('bui-sl-new-link')}
            </ButtonPrimary>
          </>
        }
      />
      {noLinks ? (
        <EmptyState title={t('bui-sl-no-links')} description={t('bui-sl-no-links-desc')} />
      ) : (
        <>
          <Table noMoreResults={noMoreResults} cols={cols} body={body} />
          <Pagination
            itemsCount={links.length}
            offset={paginate.offset}
            onPrevClick={() => {
              setPaginate({
                offset: paginate.offset - pageLimit,
              });
            }}
            onNextClick={() => {
              setPaginate({
                offset: paginate.offset + pageLimit,
              });
            }}
          />
          <ConfirmationModal
            title={t('bui-sl-delete-link-title')}
            description={t('bui-sl-delete-link-desc')}
            visible={showDelModal}
            onConfirm={() => deleteSetupLink()}
            onCancel={() => {
              setDelModal(false);
              setSetupLink(null);
            }}
          />
          <ConfirmationModal
            title={t('bui-sl-regen-link-title')}
            description={t('bui-sl-regen-link-desc')}
            visible={showRegenModal}
            onConfirm={() => regenerateSetupLink()}
            onCancel={() => {
              setShowRegenModal(false);
              setSetupLink(null);
            }}
            actionButtonText={t('bui-sl-regenerate')!}
          />
          {setupLink && (
            <SetupLinkInfoModal
              setupLink={setupLink}
              visible={showSetupLink}
              onClose={() => {
                setShowSetupLink(false);
                setSetupLink(null);
              }}
            />
          )}
        </>
      )}
    </div>
  );
};
