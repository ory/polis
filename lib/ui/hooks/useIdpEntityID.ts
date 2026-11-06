import useSWR from 'swr';
import { useRouter } from 'next/router';

import { fetcher } from '@lib/ui/utils';
import type { ApiError, ApiSuccess } from 'types';

const useIdpEntityID = (setupLinkToken?: string) => {
  const { query, isReady } = useRouter();

  const token = setupLinkToken || (isReady ? query.token : null);

  const { data, error, isLoading } = useSWR<ApiSuccess<{ idpEntityID: string }>, ApiError>(
    token ? `/api/setup/${token}/sso-connection/idp-entityid` : null,
    fetcher
  );

  return {
    idpEntityID: data?.data.idpEntityID,
    isLoading,
    error,
  };
};

export default useIdpEntityID;
