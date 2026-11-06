import Ripemd160 from 'ripemd160';
import { Index } from '../typings';

export const parsePGOptions = (url: string) => {
  const parsedUrl = new URL(url);

  const queryParams: Record<string, any> = {};
  parsedUrl.searchParams.forEach((value, key) => {
    if (key.startsWith('pool_')) {
      key = key.replace('pool_', '');
    }
    if (key === 'max_conn_lifetime') {
      queryParams['maxLifetimeSeconds'] = parseDurationSeconds(value);
    } else if (key === 'application_name') {
      queryParams['applicationName'] = value;
    } else {
      queryParams[key] = parseInt(value, 10);
    }
  });

  return queryParams;
};

const parseDurationSeconds = (duration: string): number => {
  const durationRegex = /(\d+)([smhd])/g;
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  let totalSeconds = 0;
  let match;
  while ((match = durationRegex.exec(duration)) !== null) {
    const value = parseInt(match[1], 10);
    const unit = match[2];
    totalSeconds += value * (units[unit] || 0);
  }
  return totalSeconds;
};

export const key = (namespace: string, k: string): string => {
  return namespace + ':' + k;
};

export const keyForIndex = (namespace: string, idx: Index): string => {
  return key(key(namespace, idx.name), idx.value);
};

export const keyDigest = (k: string): string => {
  return new Ripemd160().update(k).digest('hex');
};

export const keyFromParts = (...parts: string[]): string => {
  return parts.join(':');
};

export const sleep = (ms: number): Promise<void> => {
  return new Promise((resolve) => setTimeout(resolve, ms));
};
function isNumeric(num) {
  return !isNaN(num);
}
export const normalizeOffsetAndLimit = ({
  pageLimit,
  pageOffset,
  maxLimit,
}: {
  pageOffset?: number;
  pageLimit?: number;
  maxLimit: number;
}) => {
  const skipOffset = pageOffset === undefined || !isNumeric(pageOffset);
  // maxLimit capped to 50 by default unless set from env (db.options.pageLimit)
  const capToMaxLimit =
    pageLimit === undefined || pageLimit === 0 || !isNumeric(pageLimit) || pageLimit > maxLimit;

  return { offset: skipOffset ? 0 : pageOffset, limit: capToMaxLimit ? maxLimit : pageLimit };
};
export const indexPrefix = '_index';
export const createdAtPrefix = '_createdAt';
