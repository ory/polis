import type { NextRouter } from 'next/router';
import { useState, useEffect } from 'react';

// TODO:
// https://nextjs.org/docs/messages/next-router-not-mounted
// Accepting router is a temp workaround to handle Router not mounted error

export const usePaginate = (router: NextRouter) => {
  const offset = router.query.offset ? Number(router.query.offset) : 0;

  const [paginate, setPaginate] = useState({ offset });
  const [pageTokenMap, setPageTokenMap] = useState({});

  // When the offset changes in the URL (external navigation), reset paginate by
  // adjusting state during render instead of synchronizing it in an effect.
  const [prevOffset, setPrevOffset] = useState(offset);
  if (offset !== prevOffset) {
    setPrevOffset(offset);
    setPaginate({ offset });
  }

  useEffect(() => {
    // Prevent pushing the same URL to the history
    if (offset === paginate.offset) {
      return;
    }

    const path = router.asPath.split('?')[0];

    router.push(`${path}?offset=${paginate.offset}`, undefined, { shallow: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paginate]);

  return {
    paginate,
    setPaginate,
    pageTokenMap,
    setPageTokenMap,
  };
};
