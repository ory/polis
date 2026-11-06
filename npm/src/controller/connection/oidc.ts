import crypto from 'crypto';
import {
  IConnectionAPIController,
  OIDCSSOConnectionWithDiscoveryUrl,
  OIDCSSOConnectionWithMetadata,
  OIDCSSORecord,
  Storable,
  UpdateOIDCConnectionParams,
} from '../../typings';
import * as dbutils from '../../db/utils';
import {
  extractHostName,
  extractRedirectUrls,
  IndexNames,
  validateSSOConnection,
  validateRedirectUrl,
  validateTenantAndProduct,
  validateSortOrder,
} from '../utils';
import { JacksonError } from '../error';

const oidc = {
  create: async (
    body: OIDCSSOConnectionWithDiscoveryUrl | OIDCSSOConnectionWithMetadata,
    connectionStore: Storable
  ) => {
    validateSSOConnection(body, 'oidc');

    const {
      defaultRedirectUrl,
      redirectUrl,
      tenant,
      product,
      name,
      label,
      description,
      oidcDiscoveryUrl = '',
      oidcMetadata = { issuer: '' },
      oidcClientId = '',
      oidcClientSecret = '',
    } = body;

    let connectionClientSecret: string;

    const redirectUrlList = extractRedirectUrls(redirectUrl);

    validateRedirectUrl({ defaultRedirectUrl, redirectUrlList });

    validateTenantAndProduct(tenant, product);

    if ('sortOrder' in body) {
      validateSortOrder(body.sortOrder);
    }

    const record: Partial<OIDCSSORecord> = {
      defaultRedirectUrl,
      redirectUrl: redirectUrlList,
      tenant,
      product,
      name,
      label,
      description,
      clientID: '',
      clientSecret: '',
      sortOrder: parseInt(body.sortOrder as any),
    };

    //  from OpenID Provider
    record.oidcProvider = {
      clientId: oidcClientId,
      clientSecret: oidcClientSecret,
    } as OIDCSSORecord['oidcProvider'];

    if (oidcDiscoveryUrl) {
      record.oidcProvider.discoveryUrl = oidcDiscoveryUrl;
    } else if (oidcMetadata.issuer) {
      record.oidcProvider.metadata = oidcMetadata;
    }

    // extract provider
    const providerName = extractHostName(oidcDiscoveryUrl || oidcMetadata.issuer);
    record.oidcProvider.provider = providerName ? providerName : 'Unknown';

    // Use the clientId from the OpenID Provider to generate the clientID hash for the connection
    record.clientID = dbutils.keyDigest(dbutils.keyFromParts(tenant, product, oidcClientId));

    const exists = await connectionStore.get(record.clientID);

    if (exists) {
      connectionClientSecret = exists.clientSecret;
    } else {
      connectionClientSecret = crypto.randomBytes(24).toString('hex');
    }

    record.clientSecret = connectionClientSecret;

    await connectionStore.put(
      record.clientID,
      record,
      {
        // secondary index on tenant + product
        name: IndexNames.TenantProduct,
        value: dbutils.keyFromParts(tenant, product),
      },
      {
        // secondary index on product
        name: IndexNames.Product,
        value: product,
      }
    );

    return record as OIDCSSORecord;
  },

  update: async (
    body: UpdateOIDCConnectionParams,
    connectionStore: Storable,
    connectionsGetter: IConnectionAPIController['getConnections']
  ) => {
    const {
      defaultRedirectUrl,
      redirectUrl,
      name,
      label,
      description,
      oidcDiscoveryUrl,
      oidcMetadata,
      oidcClientId,
      oidcClientSecret,
      ...clientInfo
    } = body;

    if (
      !(clientInfo?.clientID && clientInfo?.clientSecret) &&
      !(clientInfo?.tenant && clientInfo?.product && clientInfo?.clientSecret)
    ) {
      throw new JacksonError('Please provide clientID/clientSecret or tenant/product/clientSecret', 400);
    }

    if (description && description.length > 100) {
      throw new JacksonError('Description should not exceed 100 characters', 400);
    }

    if ('sortOrder' in body) {
      validateSortOrder(body.sortOrder);
    }

    const redirectUrlList = redirectUrl ? extractRedirectUrls(redirectUrl) : null;
    validateRedirectUrl({ defaultRedirectUrl, redirectUrlList });

    const _savedConnection = (await connectionsGetter(clientInfo))[0] as OIDCSSORecord;

    if (_savedConnection.clientSecret !== clientInfo?.clientSecret) {
      throw new JacksonError('clientSecret mismatch', 400);
    }

    let oidcProvider;
    if (_savedConnection && typeof _savedConnection.oidcProvider === 'object') {
      oidcProvider = { ..._savedConnection.oidcProvider };

      if (oidcClientId && typeof oidcClientId === 'string') {
        const clientID = dbutils.keyDigest(
          dbutils.keyFromParts(clientInfo.tenant, clientInfo.product, oidcClientId)
        );
        if (clientID !== clientInfo?.clientID) {
          throw new JacksonError('Tenant/Product config mismatch with OIDC Provider metadata', 400);
        }
      }

      if (oidcClientSecret && typeof oidcClientSecret === 'string') {
        oidcProvider.clientSecret = oidcClientSecret;
      }

      if (oidcDiscoveryUrl && typeof oidcDiscoveryUrl === 'string') {
        oidcProvider.discoveryUrl = oidcDiscoveryUrl;
        const providerName = extractHostName(oidcDiscoveryUrl);
        oidcProvider.provider = providerName ? providerName : 'Unknown';
        // Remove previous metadata if any
        delete oidcProvider.metadata;
      } else if (oidcMetadata && typeof oidcMetadata === 'object') {
        // Perform a merge of new metadata with existing one
        oidcProvider.metadata = { ...oidcProvider.metadata, ...oidcMetadata };
        const providerName = extractHostName(oidcMetadata.issuer);
        oidcProvider.provider = providerName ? providerName : 'Unknown';
        // Remove previous discoveryUrl if any
        delete oidcProvider.discoveryUrl;
      }
    }

    const record: OIDCSSORecord = {
      ..._savedConnection,
      name: name || name === '' ? name : _savedConnection.name,
      label: label || label === '' ? label : _savedConnection.label,
      description: description || description === '' ? description : _savedConnection.description,
      defaultRedirectUrl: defaultRedirectUrl ? defaultRedirectUrl : _savedConnection.defaultRedirectUrl,
      redirectUrl: redirectUrlList ? redirectUrlList : _savedConnection.redirectUrl,
      oidcProvider: oidcProvider ? oidcProvider : _savedConnection.oidcProvider,
    };

    if ('sortOrder' in body) {
      record.sortOrder = parseInt(body.sortOrder as any);
    }

    if ('deactivated' in body) {
      record['deactivated'] = body.deactivated;
    }

    await connectionStore.put(
      clientInfo?.clientID || _savedConnection.clientID,
      record,
      {
        // secondary index on tenant + product
        name: IndexNames.TenantProduct,
        value: dbutils.keyFromParts(_savedConnection.tenant, _savedConnection.product),
      },
      {
        // secondary index on product
        name: IndexNames.Product,
        value: _savedConnection.product,
      }
    );

    return record;
  },
};

export default oidc;
