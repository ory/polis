import crypto from 'crypto';
import saml20 from '@boxyhq/saml20';
import axios from 'axios';
import ipaddr from 'ipaddr.js';

import {
  IConnectionAPIController,
  SAMLSSOConnectionWithEncodedMetadata,
  SAMLSSOConnectionWithRawMetadata,
  SAMLSSORecord,
  Storable,
  UpdateSAMLConnectionParams,
} from '../../typings';
import * as dbutils from '../../db/utils';
import {
  extractHostName,
  extractRedirectUrls,
  IndexNames,
  validateSSOConnection,
  validateRedirectUrl,
  validateTenantAndProduct,
  isLocalhost,
  validateSortOrder,
  isHTTPS,
  validateSSOURL,
} from '../utils';
import { JacksonError } from '../error';

async function fetchMetadata(resource: string) {
  try {
    const response = await axios(resource, {
      maxContentLength: 1000000,
      maxBodyLength: 1000000,
      timeout: 8000,
    });
    return response.data;
  } catch (err: any) {
    throw new JacksonError("Couldn't fetch XML data", err.response?.status || 400);
  }
}

function validateParsedMetadata(metadata: SAMLSSORecord['idpMetadata']) {
  if (metadata.loginType !== 'idp') {
    throw new JacksonError('Please provide a metadata with IDPSSODescriptor', 400);
  }

  if (!metadata.entityID) {
    throw new JacksonError("Couldn't parse EntityID from SAML metadata", 400);
  }

  if (!metadata.sso.redirectUrl && !metadata.sso.postUrl) {
    throw new JacksonError("Couldn't find SAML bindings for POST/REDIRECT", 400);
  }

  if (metadata.sso.redirectUrl) {
    validateSSOURL(metadata.sso.redirectUrl);
  }
  if (metadata.sso.postUrl) {
    validateSSOURL(metadata.sso.postUrl);
  }
}

function isPrivateIP(url: string): boolean {
  let ip: string;
  let addr: ipaddr.IPv4 | ipaddr.IPv6;

  try {
    const givenURL = new URL(url);
    ip = givenURL.host.split(':')[0];

    addr = ipaddr.parse(ip);
  } catch {
    return false;
  }

  const kind = addr.kind();
  const range = addr.range();

  if (kind === 'ipv4') {
    if (range === 'private') {
      throw new JacksonError('Metadata URL not valid, private IPs are not allowed', 400);
    }
  } else if (kind === 'ipv6') {
    if (range === 'uniqueLocal') {
      throw new JacksonError('Metadata URL not valid, private IPs are not allowed', 400);
    }
  }

  return false;
}

function validateMetadataURL(metadataUrl: string) {
  if (!isLocalhost(metadataUrl) && !isHTTPS(metadataUrl)) {
    throw new JacksonError('Metadata URL not valid, allowed ones are localhost/HTTPS URLs', 400);
  }

  return !isPrivateIP(metadataUrl);
}

const saml = {
  create: async (
    body: SAMLSSOConnectionWithRawMetadata | SAMLSSOConnectionWithEncodedMetadata,
    connectionStore: Storable
  ) => {
    const {
      encodedRawMetadata,
      rawMetadata,
      defaultRedirectUrl,
      redirectUrl,
      tenant,
      product,
      name,
      label,
      description,
      metadataUrl,
      identifierFormat,
      acsUrlOverride,
      samlAudienceOverride,
    } = body;
    const forceAuthn = body.forceAuthn == 'true' || body.forceAuthn == true;

    let connectionClientSecret: string;

    validateSSOConnection(body, 'saml');

    const redirectUrlList = extractRedirectUrls(redirectUrl);

    validateRedirectUrl({ defaultRedirectUrl, redirectUrlList });

    validateTenantAndProduct(tenant, product);

    if ('sortOrder' in body) {
      validateSortOrder(body.sortOrder);
    }

    const record: Partial<SAMLSSORecord> = {
      defaultRedirectUrl,
      redirectUrl: redirectUrlList,
      tenant,
      product,
      name,
      label,
      description,
      clientID: '',
      clientSecret: '',
      forceAuthn,
      identifierFormat,
      metadataUrl,
      sortOrder: parseInt(body.sortOrder as any),
      acsUrlOverride,
      samlAudienceOverride,
    };

    let metadata = rawMetadata as string;
    if (encodedRawMetadata) {
      metadata = Buffer.from(encodedRawMetadata, 'base64').toString();
    }

    metadataUrl && validateMetadataURL(metadataUrl);

    metadata = metadataUrl ? await fetchMetadata(metadataUrl) : metadata;

    const idpMetadata = (await saml20.parseMetadata(metadata, {})) as SAMLSSORecord['idpMetadata'];

    validateParsedMetadata(idpMetadata);

    // extract provider
    let providerName = extractHostName(idpMetadata.entityID);
    if (!providerName) {
      providerName = extractHostName(idpMetadata.sso.redirectUrl || idpMetadata.sso.postUrl || '');
    }

    idpMetadata.provider = providerName ? providerName : 'Unknown';

    record.clientID = dbutils.keyDigest(dbutils.keyFromParts(tenant, product, idpMetadata.entityID));

    record.idpMetadata = idpMetadata;

    const existing = (
      await connectionStore.getByIndex({
        name: IndexNames.EntityID,
        value: idpMetadata.entityID,
      })
    ).data;

    if (existing.length > 0) {
      for (let i = 0; i < existing.length; i++) {
        if (existing[i].tenant !== tenant) {
          throw new JacksonError('EntityID already exists for different tenant');
        }
      }
    }

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
        name: IndexNames.EntityID, // secondary index on entityID
        value: idpMetadata.entityID,
      },
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

    return record as SAMLSSORecord;
  },

  update: async (
    body: UpdateSAMLConnectionParams,
    connectionStore: Storable,
    connectionsGetter: IConnectionAPIController['getConnections']
  ) => {
    const {
      encodedRawMetadata, // could be empty
      rawMetadata, // could be empty
      defaultRedirectUrl,
      redirectUrl,
      name,
      label,
      description,
      forceAuthn,
      metadataUrl,
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

    const _savedConnection = (await connectionsGetter(clientInfo))[0] as SAMLSSORecord;

    if (_savedConnection.clientSecret !== clientInfo?.clientSecret) {
      throw new JacksonError('clientSecret mismatch', 400);
    }

    let metadata = rawMetadata;
    if (encodedRawMetadata) {
      metadata = Buffer.from(encodedRawMetadata, 'base64').toString();
    }

    metadataUrl && validateMetadataURL(metadataUrl);

    metadata = metadataUrl ? await fetchMetadata(metadataUrl) : metadata;

    let newMetadata, newMetadataUrl;
    if (metadata) {
      newMetadata = await saml20.parseMetadata(metadata, {});

      validateParsedMetadata(newMetadata);

      // extract provider
      let providerName = extractHostName(newMetadata.entityID);
      if (!providerName) {
        providerName = extractHostName(newMetadata.sso.redirectUrl || newMetadata.sso.postUrl);
      }

      newMetadata.provider = providerName ? providerName : 'Unknown';
    }

    if (newMetadata) {
      // check if clientID matches with new metadata payload
      const clientID = dbutils.keyDigest(
        dbutils.keyFromParts(clientInfo.tenant, clientInfo.product, newMetadata.entityID)
      );

      if (clientID !== clientInfo?.clientID) {
        throw new JacksonError('Tenant/Product config mismatch with IdP metadata', 400);
      }

      if (metadataUrl) {
        newMetadataUrl = metadataUrl;
      }
    }

    const record: SAMLSSORecord = {
      ..._savedConnection,
      name: name || name === '' ? name : _savedConnection.name,
      label: label || label === '' ? label : _savedConnection.label,
      description: description || description === '' ? description : _savedConnection.description,
      idpMetadata: newMetadata ? newMetadata : _savedConnection.idpMetadata,
      metadataUrl: newMetadata ? newMetadataUrl : _savedConnection.metadataUrl,
      defaultRedirectUrl: defaultRedirectUrl ? defaultRedirectUrl : _savedConnection.defaultRedirectUrl,
      redirectUrl: redirectUrlList ? redirectUrlList : _savedConnection.redirectUrl,
      forceAuthn: typeof forceAuthn === 'boolean' ? forceAuthn : _savedConnection.forceAuthn,
    };

    if ('sortOrder' in body) {
      record.sortOrder = parseInt(body.sortOrder as any);
    }

    if ('deactivated' in body) {
      record['deactivated'] = body.deactivated;
    }

    if ('identifierFormat' in body) {
      record['identifierFormat'] = body.identifierFormat;
    }

    if ('acsUrlOverride' in body) {
      record['acsUrlOverride'] = body.acsUrlOverride;
    }

    if ('samlAudienceOverride' in body) {
      record['samlAudienceOverride'] = body.samlAudienceOverride;
    }

    await connectionStore.put(
      clientInfo?.clientID || _savedConnection.clientID,
      record,
      {
        // secondary index on entityID
        name: IndexNames.EntityID,
        value: _savedConnection.idpMetadata.entityID,
      },
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

export default saml;
