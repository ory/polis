export function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text);
}

export const defaultHeaders = {
  'Content-Type': 'application/json',
};

export const fetcher = async (url: string, queryParams = '') => {
  const res = await fetch(`${url}${queryParams}`);

  let resContent, pageToken;

  try {
    resContent = await res.clone().json();
    pageToken = res.headers.get('jackson-pagetoken');
    if (pageToken !== null) {
      return { ...resContent, pageToken };
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (e) {
    resContent = await res.clone().text();
  }

  if (!res.ok) {
    const error = new Error(
      (resContent.error.message as string) || 'An error occurred while fetching the data.'
    );

    throw error;
  }

  return resContent;
};

export const addQueryParamsToPath = (path: string, queryParams: Record<string, any>) => {
  const hasQuery = path.includes('?');

  const queryString = Object.keys(queryParams)
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
    .join('&');

  const newPath = hasQuery ? `${path}&${queryString}` : `${path}?${queryString}`;

  return newPath;
};
