import useSWR from 'swr';
import { useEffect, useState } from 'react';
import { useTranslation } from 'next-i18next';
import EyeIcon from '@heroicons/react/24/outline/EyeIcon';
import { ApiSuccess, type WebhookEventLog } from '../types';
import { fetcher, addQueryParamsToPath } from '../utils';
import { DirectoryTab } from '../dsync';
import { usePaginate, useDirectory } from '../hooks';
import { TableBodyType } from '../shared/Table';
import {
  Loading,
  Table,
  EmptyState,
  Error,
  Pagination,
  PageHeader,
  pageLimit,
  ConfirmationModal,
} from '../shared';
import { ButtonDanger } from '../shared/ButtonDanger';
import { useRouter } from '../hooks';

export const DirectoryWebhookLogs = ({
  urls,
  onView,
  onDelete,
}: {
  urls: { getEvents: string; getDirectory: string; tabBase: string; deleteEvents?: string };
  onView?: (event: WebhookEventLog) => void;
  onDelete?: () => void;
}) => {
  const { router } = useRouter();
  const { t } = useTranslation('common');
  const [delModalVisible, setDelModalVisible] = useState(false);
  const { paginate, setPaginate, pageTokenMap, setPageTokenMap } = usePaginate(router!);

  const params = {
    pageOffset: paginate.offset,
    pageLimit,
  };

  // For DynamoDB
  // Use the (next)pageToken mapped to the previous page offset to get the current page
  if (paginate.offset > 0 && pageTokenMap[paginate.offset - pageLimit]) {
    params['pageToken'] = pageTokenMap[paginate.offset - pageLimit];
  }

  const getUrl = addQueryParamsToPath(urls.getEvents, params);

  const { directory, isLoadingDirectory, directoryError } = useDirectory(urls.getDirectory);
  const { data, isLoading, error } = useSWR<ApiSuccess<WebhookEventLog[]>>(getUrl, fetcher);

  const nextPageToken = data?.pageToken;

  useEffect(() => {
    if (nextPageToken) {
      setPageTokenMap((tokenMap) => ({ ...tokenMap, [paginate.offset]: nextPageToken }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nextPageToken, paginate.offset]);

  if (isLoading || isLoadingDirectory) {
    return <Loading />;
  }

  if (error || directoryError) {
    return <Error message={error.message || directoryError.message} />;
  }

  if (!data || !directory) {
    return null;
  }

  const events = data?.data || [];
  const noEvents = events.length === 0 && paginate.offset === 0;
  const noMoreResults = events.length === 0 && paginate.offset > 0;

  const columns = [
    {
      key: 'webhook_endpoint',
      label: t('bui-dsync-webhook-endpoint'),
      wrap: true,
      dataIndex: 'webhook_endpoint',
    },
    {
      key: 'status_code',
      label: t('bui-dsync-status-code'),
      wrap: true,
      dataIndex: 'status_code',
    },
    {
      key: 'created_at',
      label: t('bui-dsync-sent-at'),
      wrap: true,
      dataIndex: 'created_at',
    },
    {
      key: 'actions',
      label: t('bui-shared-actions'),
      wrap: true,
      dataIndex: null,
    },
  ];

  const cols = columns.map(({ label }) => label);

  const body: TableBodyType[] = events.map((event) => {
    return {
      id: event.id,
      cells: columns.map((column) => {
        const dataIndex = column.dataIndex as keyof typeof event;

        if (dataIndex === null) {
          return {
            actions: [
              {
                text: t('bui-shared-view'),
                onClick: () => onView?.(event),
                icon: <EyeIcon className='w-5' />,
              },
            ],
          };
        }

        if (dataIndex === 'status_code') {
          return {
            badge: {
              text: event[dataIndex] as any,
              color: event[dataIndex] === 200 ? 'success' : 'error',
            },
          };
        }

        return {
          wrap: column.wrap,
          text: event[dataIndex] as string,
        };
      }),
    };
  });

  const removeEvents = async () => {
    if (!urls.deleteEvents) {
      return;
    }

    await fetch(urls.deleteEvents, {
      method: 'DELETE',
    });

    onDelete?.();
  };

  return (
    <>
      <PageHeader title={directory.name} />
      <DirectoryTab activeTab='events' baseUrl={urls.tabBase} />
      {noEvents ? (
        <EmptyState title={t('bui-dsync-no-events')} />
      ) : (
        <>
          {urls.deleteEvents && (
            <>
              <div className='py-2 flex justify-end'>
                <ButtonDanger onClick={() => setDelModalVisible(true)}>
                  {t('bui-dsync-remove-events')}
                </ButtonDanger>
              </div>
              <ConfirmationModal
                title={t('bui-dsync-delete-events-title')}
                description={t('bui-dsync-delete-events-desc')}
                visible={delModalVisible}
                onConfirm={() => removeEvents()}
                onCancel={() => setDelModalVisible(false)}
              />
            </>
          )}
          <Table noMoreResults={noMoreResults} cols={cols} body={body} />
          <Pagination
            itemsCount={events.length}
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
        </>
      )}
    </>
  );
};
