import type { ServerMetadata, Configuration, CustomFetchOptions } from 'openid-client';
import * as http from 'http';
import * as https from 'https';
import { JacksonError } from '../error';
import { URL } from 'url';
import { SSOTrace, SSOTracesInstance } from '../../typings';
import { dynamicImport, GENERIC_ERR_STRING } from '../utils';

const createCustomFetch = (ssoTraces: { instance: SSOTracesInstance; context: SSOTrace['context'] }) => {
  return async (url: string | URL, options: CustomFetchOptions): Promise<Response> => {
    return new Promise((resolve, reject) => {
      let parsedUrl = typeof url === 'string' ? new URL(url) : url;
      const headers = new Headers(options.headers);

      // Look for a match to Ory local address, we need to rewrite that to the k8s svc
      const hostParts = parsedUrl.host.split('.');
      if (hostParts.length === 3) {
        if (hostParts[1] === 'projects' && hostParts[2] === 'oryapis:8080') {
          headers.set('Host', parsedUrl.hostname);
          parsedUrl = new URL(`http://hydra-public${parsedUrl.pathname}`);
        }
      }

      const requestOptions: https.RequestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port,
        path: parsedUrl.pathname + parsedUrl.search,
        method: options.method || 'GET',
        headers: Object.fromEntries(headers.entries()),
      };
      const request = parsedUrl.protocol === 'https:' ? https.request : http.request;

      const req = request(requestOptions, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          const response = new Response(data, {
            status: res.statusCode,
            statusText: res.statusMessage,
            headers: new Headers(res.headers as HeadersInit),
          });

          resolve(response);
        });
      });

      req.on('error', (error) => {
        ssoTraces.instance.saveTrace({
          error: `Fetch failed for OIDC IdP endpoint: ${parsedUrl.toString()}`,
          context: ssoTraces.context,
        });
        reject(error);
      });

      if (options.body) {
        let body;
        let contentType: string | undefined;

        if (options.body instanceof URLSearchParams) {
          body = options.body.toString();
          contentType = 'application/x-www-form-urlencoded';
        } else {
          body = options.body;
        }

        if (contentType) {
          req.setHeader('content-type', contentType);
        }
        req.write(body);
      }
      req.end();
    });
  };
};

export const oidcClientConfig = async ({
  discoveryUrl,
  metadata,
  clientId,
  clientSecret,
  ssoTraces,
}: {
  discoveryUrl?: string;
  metadata?: ServerMetadata;
  clientId: string;
  clientSecret: string;
  ssoTraces: { instance: SSOTracesInstance; context: SSOTrace['context'] };
}): Promise<Configuration> => {
  const url = discoveryUrl ? new URL(discoveryUrl) : new URL(metadata!.issuer);
  const isLocalhost = url.hostname === 'localhost';
  const customFetchWithSsoTraces = createCustomFetch(ssoTraces);
  const client = (await dynamicImport('openid-client')) as typeof import('openid-client');

  if (discoveryUrl) {
    return await client.discovery(
      url,
      clientId,
      clientSecret,
      undefined,
      isLocalhost
        ? {
            execute: [client.allowInsecureRequests],
            [client.customFetch]: customFetchWithSsoTraces,
          }
        : { [client.customFetch]: customFetchWithSsoTraces }
    );
  }
  if (metadata) {
    const config = new client.Configuration(metadata, clientId, clientSecret);
    config[client.customFetch] = customFetchWithSsoTraces;
    if (isLocalhost) {
      client.allowInsecureRequests(config);
    }
    return config;
  }
  throw new JacksonError(
    GENERIC_ERR_STRING,
    500,
    'Neither "discoveryUrl" nor "metadata" set for the OIDC provider'
  );
};
