import useSWR from 'swr';
import { useTranslation } from 'next-i18next';
import EyeIcon from '@heroicons/react/24/outline/EyeIcon';
import type { ApiSuccess, Group } from '../types';
import { fetcher, addQueryParamsToPath } from '../utils';
import { DirectoryTab } from '../dsync';
import { usePaginate, useDirectory } from '../hooks';
import { TableBodyType } from '../shared/Table';
import { Loading, Table, EmptyState, Error, Pagination, PageHeader, pageLimit } from '../shared';
import { useRouter } from '../hooks';
import { useEffect } from 'react';

export const DirectoryGroups = ({
  urls,
  onView,
}: {
  urls: { getGroups: string; getDirectory: string; tabBase: string };
  onView?: (group: Group) => void;
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

  const getUrl = addQueryParamsToPath(urls.getGroups, params);

  const { directory, isLoadingDirectory, directoryError } = useDirectory(urls.getDirectory);
  const { data, isLoading, error } = useSWR<ApiSuccess<Group[]>>(getUrl, fetcher);

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

  const groups = data?.data || [];
  const noGroups = groups.length === 0 && paginate.offset === 0;
  const noMoreResults = groups.length === 0 && paginate.offset > 0;

  const columns = [
    {
      key: 'name',
      label: t('bui-shared-name'),
      wrap: true,
      dataIndex: 'name',
    },
    {
      key: 'actions',
      label: t('bui-shared-actions'),
      wrap: true,
      dataIndex: null,
    },
  ];

  const cols = columns.map(({ label }) => label);

  const body: TableBodyType[] = groups.map((group) => {
    return {
      id: group.id,
      cells: columns.map((column) => {
        const dataIndex = column.dataIndex as string;

        if (dataIndex === null) {
          return {
            actions: [
              {
                text: t('bui-shared-view'),
                onClick: () => onView?.(group),
                icon: <EyeIcon className='w-5' />,
              },
            ],
          };
        }

        return {
          wrap: column.wrap,
          text: group[dataIndex],
        };
      }),
    };
  });

  return (
    <>
      <PageHeader title={directory.name} />
      <DirectoryTab activeTab='groups' baseUrl={urls.tabBase} />
      {noGroups ? (
        <EmptyState title={t('bui-dsync-no-groups')} />
      ) : (
        <>
          <Table noMoreResults={noMoreResults} cols={cols} body={body} />
          <Pagination
            itemsCount={groups.length}
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
