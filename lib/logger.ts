import pino, { type Logger } from 'pino';
import fs from 'fs';
import { loggerOptions } from '@lib/env';

const isDevelopment = process.env.NODE_ENV !== 'production';
const g = global as any;

// Custom error serializer for production that omits stack traces
const productionErrorSerializer = ({
  message,
  statusCode = 500,
  internalError,
}: Error & { statusCode?: number; internalError?: string }) => {
  // stack trace is intentionally omitted
  const err: any = { message, statusCode };
  if (internalError) {
    err.internalError = internalError;
  }
  return err;
};

export function initLogger(logFile?: string, logLevel?: string): Logger {
  if (logFile) {
    return pino(fs.createWriteStream(logFile));
  }

  return pino({
    level: logLevel || 'info',
    timestamp: () => `,"time":"${new Date().toISOString()}"`,
    transport: isDevelopment
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
          },
        }
      : undefined,
    serializers: {
      err: isDevelopment ? pino.stdSerializers.err : productionErrorSerializer,
    },
  });
}

function initLoggerFromEnv(): Logger {
  if (!g.loggerInstance) {
    g.loggerInstance = initLogger(loggerOptions.file, loggerOptions.level);
  }
  return g.loggerInstance;
}

export const logger = initLoggerFromEnv();
