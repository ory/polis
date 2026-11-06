const redirectUrlPlaceholder = 'http://_boxyhq_redirect_not_in_use';

export const redirect = (
  redirectUrl: string,
  redirectUrls: string[],
  redirectExactMatch: boolean | undefined
): boolean => {
  // Don't allow redirect to URL placeholder
  if (redirectUrl === redirectUrlPlaceholder) {
    return false;
  }

  const url: URL = new URL(redirectUrl);

  for (const idx in redirectUrls) {
    const rUrl: URL = new URL(redirectUrls[idx]);

    let hostname = url.hostname;
    let hostNameAllowed = rUrl.hostname;

    // allow subdomain globbing *.example.com only
    try {
      if (rUrl.hostname.startsWith('*.')) {
        hostNameAllowed = rUrl.hostname.slice(2);
        hostname = hostname.slice(hostname.indexOf('.') + 1);
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      // no-op
    }

    if (redirectExactMatch) {
      // check for pathname as well
      if (
        rUrl.protocol === url.protocol &&
        hostNameAllowed === hostname &&
        rUrl.port === url.port &&
        rUrl.pathname === url.pathname
      ) {
        return true;
      }

      return false;
    }

    if (rUrl.protocol === url.protocol && hostNameAllowed === hostname && rUrl.port === url.port) {
      return true;
    }
  }

  return false;
};
