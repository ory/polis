import crypto from 'crypto';
import saml from '@boxyhq/saml20';
import * as dbutils from '../db/utils';
import claims from '../saml/claims';

// Validate the SAMLResponse and extract the user profile
export const extractSAMLResponseAttributes = async (
  decodedResponse: string,
  validateOpts: ValidateOption
) => {
  const attributes = await saml.validate(decodedResponse, validateOpts);

  if (attributes && attributes.claims) {
    // We map claims to our attributes id, email, firstName, lastName where possible. We also map original claims to raw
    attributes.claims = claims.map(attributes.claims);

    // Some providers don't return the id in the assertion, we set it to a sha256 hash of the email
    if (!attributes.claims.id && attributes.claims.email) {
      attributes.claims.id = crypto.createHash('sha256').update(attributes.claims.email).digest('hex');
    }
  }

  // we'll send a ripemd160 hash of the id, this can be used in the case of email missing it can be used as the local part
  attributes.claims.idHash = dbutils.keyDigest(attributes.claims.id);

  return attributes;
};

export type ValidateOption = {
  thumbprint?: string;
  publicKey?: string;
  audience: string;
  privateKey: string;
  inResponseTo?: string;
};
