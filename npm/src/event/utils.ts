import type {
  Directory,
  DsyncConnectionEventData,
  SAMLSSOConnectionEventData,
  OIDCSSOConnectionEventData,
  SAMLSSORecord,
  OIDCSSORecord,
} from '../typings';
import { findFriendlyProviderName } from '../controller/utils';

export const transformSAMLSSOConnection = (data: SAMLSSORecord): SAMLSSOConnectionEventData => {
  const { name, description, clientID, clientSecret, idpMetadata } = data;
  const { provider } = idpMetadata;

  return {
    name,
    description,
    clientID,
    clientSecret,
    provider,
    friendlyProviderName: findFriendlyProviderName(provider),
  };
};

export const transformOIDCSSOConnection = (data: OIDCSSORecord): OIDCSSOConnectionEventData => {
  const { name, description, clientID, clientSecret, oidcProvider } = data;
  const { provider } = oidcProvider;

  return {
    name,
    description,
    clientID,
    clientSecret,
    provider,
  };
};

export const transformDirectoryConnection = (data: Directory): DsyncConnectionEventData => {
  const { id, name, type } = data;

  return {
    id,
    name,
    type,
  };
};
