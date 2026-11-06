import useSWR from 'swr';
import { fetcher } from '../utils';
import type { Directory } from '../types';

export const useDirectory = (getDirectoryUrl: string) => {
  const { data, error, isLoading } = useSWR(getDirectoryUrl, fetcher);

  return {
    directory: data?.data as Directory & { google_authorized?: boolean },
    isLoadingDirectory: isLoading,
    directoryError: error,
  };
};
