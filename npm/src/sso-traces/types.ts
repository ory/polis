import { SAMLProfile } from '@boxyhq/saml20/dist/typings';
import SSOTraces from '.';
import { OIDCIdPInitiatedReq } from '../typings';

export interface Trace {
  traceId: string;
  timestamp: number;
  error: string;
  context: {
    [key: string]: unknown;
  };
}

export interface SSOTrace extends Omit<Trace, 'traceId' | 'timestamp'> {
  timestamp?: number /** Can be passed in from outside else will be set to Date.now() */;
  context: {
    tenant: string;
    product: string;
    clientID: string;
    redirectUri?: string;
    requestedOIDCFlow?: boolean; // Type of OAuth client request
    isSAMLFederated?: boolean; // true if hit the SAML Federation flow
    isOIDCFederated?: boolean; // true if hit the OIDC Federation flow
    isIdPFlow?: boolean; // true if IdP Login flow
    relayState?: string; // RelayState in SP flow
    providerName?: string; // SAML Federation SP
    acsUrl?: string; // ACS Url of SP in SAML Federation flow
    entityId?: string; // Entity ID of SP in SAML Federation flow
    samlRequest?: string; // Generated SAML Request
    samlResponse?: string; // Raw SAML response from IdP
    issuer?: string; // Parsed issuer from samlResponse
    profile?: SAMLProfile; // Profile extracted from samlResponse
    //  OPError attributes from OIDC provider authorization response: https://github.com/panva/node-openid-client/blob/main/docs/README.md#class-operror
    error?: string;
    error_description?: string;
    error_uri?: string;
    session_state_from_op_error?: string;
    scope_from_op_error?: string;
    stack?: string;
    oidcTokenSet?: { id_token?: string; access_token?: string };
    oidcIdPRequest?: OIDCIdPInitiatedReq;
    oAuthStage?: 'token_fetch' | 'userinfo_fetch';
  };
}

export type SSOTracesInstance = InstanceType<typeof SSOTraces>;
