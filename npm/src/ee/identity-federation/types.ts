import IdentityFederation from '.';

export type IIdentityFederationController = Awaited<ReturnType<typeof IdentityFederation>>;

export type AttributeMapping = {
  key: string;
  value: string;
};

export type IdentityFederationApp = {
  id: string;
  type?: string;
  clientID?: string;
  clientSecret?: string;
  redirectUrl?: string[] | string;
  name: string;
  tenant: string;
  product: string;
  acsUrl: string;
  entityId: string;
  logoUrl: string | null;
  faviconUrl: string | null;
  primaryColor: string | null;
  tenants?: string[]; // To support multiple tenants for a single app
  mappings?: AttributeMapping[] | null;
  samlAudienceOverride?: string | null;
  includeOidcTokensInAssertion?: boolean; // Include full OIDC tokens in SAML assertion
  ttlInMinutes?: number | null;
};

export type IdentityFederationAppWithMetadata = IdentityFederationApp & {
  metadata: {
    entityId: string;
    ssoUrl: string;
    x509cert: string;
    xml: string;
  };
};

export type AppRequestParams =
  | {
      id: string;
    }
  | {
      tenant: string;
      product: string;
      type?: string;
    };
