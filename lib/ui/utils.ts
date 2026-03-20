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
