import useSWR from 'swr';
import type { AdminPortalBranding, SetupLink } from '@boxyhq/saml-jackson';
import type { ApiError, ApiSuccess } from 'types';
import { fetcher } from '@lib/ui/utils';

const useSetupLink = (setupLinkToken: string) => {
  const url = setupLinkToken ? `/api/setup/${setupLinkToken}` : null;

  const { data, error, isLoading } = useSWR<ApiSuccess<SetupLink & AdminPortalBranding>, ApiError>(
    url,
    fetcher
  );

  return {
    setupLink: data?.data,
    isLoading,
    error,
  };
};

export default useSetupLink;
