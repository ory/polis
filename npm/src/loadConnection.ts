import * as fs from 'fs';
import * as path from 'path';
import * as url from 'url';
import {
  OIDCSSOConnectionWithDiscoveryUrl,
  OIDCSSOConnectionWithMetadata,
  SAMLSSOConnectionWithEncodedMetadata,
  SAMLSSOConnectionWithRawMetadata,
} from './typings';

type connection =
  | SAMLSSOConnectionWithEncodedMetadata
  | SAMLSSOConnectionWithRawMetadata
  | OIDCSSOConnectionWithDiscoveryUrl
  | OIDCSSOConnectionWithMetadata;

const loadConnection = async (preLoadedConnection: string): Promise<connection[]> => {
  if (preLoadedConnection.startsWith('./')) {
    preLoadedConnection = path.resolve(process.cwd(), preLoadedConnection);
  } else {
    preLoadedConnection = path.resolve(preLoadedConnection);
  }

  const files = await fs.promises.readdir(preLoadedConnection);
  const connections: connection[] = [];

  for (const idx in files) {
    const file = files[idx];
    if (file.endsWith('.js')) {
      const filePath = path.join(preLoadedConnection, file);
      const fileUrl = preLoadedConnection.startsWith('/') ? filePath : url.pathToFileURL(filePath).toString();
      const {
        default: connection,
      }: {
        default: connection;
      } = await import(/* webpackIgnore: true */ fileUrl);
      if (!('oidcDiscoveryUrl' in connection) && !('oidcMetadata' in connection)) {
        const rawMetadata = await fs.promises.readFile(
          path.join(preLoadedConnection, path.parse(file).name + '.xml'),
          'utf8'
        );
        connection.encodedRawMetadata = Buffer.from(rawMetadata, 'utf8').toString('base64');
      }

      connections.push(connection);
    }
  }

  return connections;
};

export default loadConnection;
