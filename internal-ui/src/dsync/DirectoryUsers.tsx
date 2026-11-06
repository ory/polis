import useSWR from 'swr';
import { useTranslation } from 'next-i18next';
import EyeIcon from '@heroicons/react/24/outline/EyeIcon';
import type { ApiSuccess, User } from '../types';
import { addQueryParamsToPath, fetcher } from '../utils';
import { DirectoryTab } from '../dsync';
import { usePaginate, useDirectory } from '../hooks';
import { TableBodyType } from '../shared/Table';
import { Loading, Table, EmptyState, Error, Pagination, PageHeader, pageLimit } from '../shared';
import { useRouter } from '../hooks';
import { useEffect } from 'react';

export const DirectoryUsers = ({
  urls,
  onView,
}: {
  urls: { getUsers: string; getDirectory: string; tabBase: string };
  onView?: (user: User) => void;
}) => {
  const { router } = useRouter();
  const { t } = useTranslation('common');
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

  const getUrl = addQueryParamsToPath(urls.getUsers, params);

  const { directory, isLoadingDirectory, directoryError } = useDirectory(urls.getDirectory);
  const { data, isLoading, error } = useSWR<ApiSuccess<User[]>>(getUrl, fetcher);

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

  const users = data?.data || [];
  const noUsers = users.length === 0 && paginate.offset === 0;
  const noMoreResults = users.length === 0 && paginate.offset > 0;

  const columns = [
    {
      key: 'first_name',
      label: t('bui-dsync-first-name'),
      wrap: true,
      dataIndex: 'first_name',
    },
    {
      key: 'last_name',
      label: t('bui-dsync-last-name'),
      wrap: true,
      dataIndex: 'last_name',
    },
    {
      key: 'email',
      label: t('bui-shared-email'),
      wrap: true,
      dataIndex: 'email',
    },
    {
      key: 'status',
      label: t('bui-shared-status'),
      wrap: true,
      dataIndex: 'active',
    },
    {
      key: 'actions',
      label: t('bui-shared-actions'),
      wrap: true,
      dataIndex: null,
    },
  ];

  const cols = columns.map(({ label }) => label);

  const body: TableBodyType[] = users.map((user) => {
    return {
      id: user.id,
      cells: columns.map((column) => {
        const dataIndex = column.dataIndex as string;

        if (dataIndex === null) {
          return {
            actions: [
              {
                text: t('bui-shared-view'),
                onClick: () => onView?.(user),
                icon: <EyeIcon className='w-5' />,
              },
            ],
          };
        }

        if (dataIndex === 'active') {
          return {
            badge: {
              text: user[dataIndex] ? t('bui-shared-active') : t('bui-dsync-suspended'),
              color: user[dataIndex] ? 'success' : 'warning',
            },
          };
        }

        return {
          wrap: column.wrap,
          text: user[dataIndex],
        };
      }),
    };
  });

  return (
    <>
      <PageHeader title={directory.name} />
      <DirectoryTab activeTab='users' baseUrl={urls.tabBase} />
      {noUsers ? (
        <EmptyState title={t('bui-dsync-no-users')} />
      ) : (
        <>
          <Table noMoreResults={noMoreResults} cols={cols} body={body} />
          <Pagination
            itemsCount={users.length}
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
