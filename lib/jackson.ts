import type { SAMLJackson } from '@boxyhq/saml-jackson';

import jackson from '@boxyhq/saml-jackson';
import { jacksonOptions } from '@lib/env';
import '@lib/metrics';
import { logger } from './logger';

const g = global as any;

const jacksonOptionsWithLogger = {
  ...jacksonOptions,
  logger: {
    info: (msg: string, err?: any) => logger.info(err, msg),
    error: (msg: string, err?: any) => logger.error(err, msg),
    warn: (msg: string, err?: any) => logger.warn(err, msg),
  },
};

export default async function init() {
  if (!g.jacksonInstance) {
    g.jacksonInstance = new Promise((resolve, reject) => {
      jackson(jacksonOptionsWithLogger).then(resolve).catch(reject);
    });
  }

  return (await g.jacksonInstance) as SAMLJackson;
}
