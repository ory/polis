export const sessionName = 'next-auth.saml-jackson';

export const identityProviders = [
  {
    name: 'Auth0 SAML SSO',
    id: 'auth0',
    stepCount: 3,
    steps: ['Create Application', 'Configure Application', 'Create SAML Connection'],
  },
  {
    name: 'Entra ID SAML SSO',
    id: 'azure',
    stepCount: 4,
    steps: ['Create Application', 'Configure Application', 'Attribute Mapping', 'Create SAML Connection'],
  },
  {
    name: 'Google SAML SSO',
    id: 'google',
    stepCount: 4,
    steps: ['Create Application', 'Configure Application', 'Attribute Mapping', 'Create SAML Connection'],
  },
  {
    name: 'JumpCloud SAML SSO',
    id: 'jumpcloud',
    stepCount: 4,
    steps: ['Create Application', 'Configure Application', 'Attribute Mapping', 'Create SAML Connection'],
  },
  {
    name: 'Microsoft AD FS SAML SSO',
    id: 'microsoft-adfs',
    stepCount: 4,
    steps: [
      'Create a claims aware Relying Party Trust using federation metadata',
      'Attribute Mapping',
      'Transform Rule',
      'Create SAML Connection',
    ],
  },
  {
    name: 'Okta SAML SSO',
    id: 'okta',
    stepCount: 4,
    steps: ['Create Application', 'Configure Application', 'Attribute Mapping', 'Create SAML Connection'],
  },
  {
    name: 'OneLogin SAML SSO',
    id: 'onelogin',
    stepCount: 4,
    steps: ['Create Application', 'Configure Application', 'Attribute Mapping', 'Create SAML Connection'],
  },
  {
    name: 'PingOne SAML SSO',
    id: 'pingone',
    stepCount: 4,
    steps: ['Create Application', 'Configure Application', 'Attribute Mapping', 'Create SAML Connection'],
  },
  {
    name: 'Rippling SAML SSO',
    id: 'rippling',
    stepCount: 3,
    steps: ['Create Application', 'Configure Application', 'Create SAML Connection'],
  },
  {
    name: 'Generic SAML 2.0',
    id: 'generic-saml',
    stepCount: 3,
    steps: [
      'Configuration SAML Application',
      'SAML Profile/Claims/Attributes Mapping',
      'Create SAML Connection',
    ],
  },
  {
    name: 'OIDC Provider',
    id: 'generic-oidc',
    stepCount: 2,
    steps: ['Create Application', 'Create OIDC Connection'],
  },
];
