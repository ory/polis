import { useEffect, useState } from 'react';

type RefetchFunction = () => void;

export async function parseResponseContent(response: Response) {
  const responseText = await response.text();

  try {
    return responseText.length ? JSON.parse(responseText) : '';
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (err) {
    return responseText;
  }
}

export function useFetch<T>({ url }: { url?: string }): {
  data?: T;
  isLoading: boolean;
  error: any;
  refetch: RefetchFunction;
} {
  const [data, setData] = useState<T>();
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<any>(null);
  const [refetchIndex, setRefetchIndex] = useState<number>(0);

  const refetch = () => setRefetchIndex((prevRefetchIndex) => prevRefetchIndex + 1);

  useEffect(() => {
    async function fetchData() {
      setIsLoading(true);
      const res = await fetch(url!);
      setIsLoading(false);
      const resContent = await parseResponseContent(res);

      if (res.ok) {
        const pageToken = res.headers.get('jackson-pagetoken');
        if (pageToken !== null) {
          setData({ ...resContent, pageToken });
        } else {
          setData(resContent);
        }
      } else {
        setError(resContent.error);
      }
    }
    if (url) {
      fetchData();
    }
  }, [url, refetchIndex]);

  return { data, isLoading, error, refetch };
}
