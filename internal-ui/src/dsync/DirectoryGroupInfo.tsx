import useSWR from 'swr';
import type { Group } from '../types';
import { fetcher } from '../utils';
import { useDirectory } from '../hooks';
import { DirectoryTab } from '../dsync';
import { Loading, Error, PageHeader, PrismLoader } from '../shared';

export const DirectoryGroupInfo = ({
  urls,
}: {
  urls: { getGroup: string; getDirectory: string; tabBase: string };
}) => {
  const { directory, isLoadingDirectory, directoryError } = useDirectory(urls.getDirectory);
  const { data, isLoading, error } = useSWR<{ data: Group }>(urls.getGroup, fetcher);

  if (isLoading || isLoadingDirectory) {
    return <Loading />;
  }

  if (error || directoryError) {
    return <Error message={error.message || directoryError.message} />;
  }

  if (!data || !directory) {
    return null;
  }

  const group = data.data;

  return (
    <>
      <PageHeader title={directory.name} />
      <DirectoryTab activeTab='groups' baseUrl={urls.tabBase} />
      <div className='text-sm'>
        <pre className='language-json'>
          <code className='language-json'>{JSON.stringify(group, null, 2)}</code>
        </pre>
      </div>

      <PrismLoader></PrismLoader>
    </>
  );
};
