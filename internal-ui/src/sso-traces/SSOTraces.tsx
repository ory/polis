import useSWR from 'swr';
import { useEffect } from 'react';
import { useTranslation } from 'next-i18next';

import type { Trace } from '../types';
import { usePaginate, useRouter } from '../hooks';
import type { ApiError, ApiSuccess } from '../types';
import { addQueryParamsToPath, fetcher } from '../utils';
import { Loading, Table, EmptyState, Error, Pagination, PageHeader, pageLimit } from '../shared';

export const SSOTraces = ({
  urls,
  onView,
}: {
  urls: { getTraces: string };
  onView: (user: Trace) => void;
}) => {
  const { router } = useRouter();
  const { t } = useTranslation('common');
  const { paginate, setPaginate, pageTokenMap, setPageTokenMap } = usePaginate(router!);

  const params = {
    pageOffset: paginate.offset,
    pageLimit,
  };

  // For DynamoDB
  if (paginate.offset > 0 && pageTokenMap[paginate.offset - pageLimit]) {
    params['pageToken'] = pageTokenMap[paginate.offset - pageLimit];
  }

  const getUrl = addQueryParamsToPath(urls.getTraces, params);
  const { data, isLoading, error } = useSWR<ApiSuccess<Trace[]>, ApiError>(getUrl, fetcher);

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

  const traces = data?.data || [];
  const noTraces = traces.length === 0 && paginate.offset === 0;
  const noMoreResults = traces.length === 0 && paginate.offset > 0;

  const cols = [
    t('bui-traces-id'),
    t('bui-traces-description'),
    t('bui-traces-assertion-type'),
    t('bui-traces-timestamp'),
  ];

  const body = traces.map((trace) => {
    return {
      id: trace.traceId,
      cells: [
        {
          wrap: true,
          element: (
            <button className='link-primary link flex' onClick={() => onView(trace)}>
              {trace.traceId}
            </button>
          ),
        },
        {
          wrap: true,
          text: trace.error,
        },
        {
          wrap: true,
          text: trace.context?.samlResponse
            ? t('bui-traces-response')
            : trace?.context.samlRequest
              ? t('bui-traces-request')
              : '-',
        },
        {
          wrap: true,
          text: new Date(trace.timestamp).toLocaleString(),
        },
      ],
    };
  });

  return (
    <div className='space-y-3'>
      <PageHeader title={t('bui-traces-title')} />
      {noTraces ? (
        <EmptyState title={t('bui-traces-no-traces')} />
      ) : (
        <>
          <Table noMoreResults={noMoreResults} cols={cols} body={body} />
          <Pagination
            itemsCount={traces.length}
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
    </div>
  );
};
