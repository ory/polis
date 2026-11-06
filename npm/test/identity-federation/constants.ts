import * as dbutils from '../../src/db/utils';

const tenant = 'boxyhq';
const product = 'flex';

const serviceProvider = {
  acsUrl: 'https://twilio.com/saml2/acs',
  entityId: 'https://twilio.com/saml2/entityId',
};

const appId = dbutils.keyDigest(dbutils.keyFromParts(tenant, product));

export { tenant, product, serviceProvider, appId };
