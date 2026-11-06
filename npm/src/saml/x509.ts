import * as forge from 'node-forge';
import crypto from 'crypto';

import type { JacksonOption, Storable } from '../typings';

const pki = forge.pki;
let certificateStore: Storable;
let cachedCertificate: { publicKey: string; privateKey: string };
let jacksonOption: JacksonOption;

export const init = async (store: Storable, opts: JacksonOption) => {
  certificateStore = store;
  jacksonOption = opts;

  return await getDefaultCertificate();
};

const generateCertificate = () => {
  const today = new Date();
  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(today.setFullYear(today.getFullYear() + 30));

  const attrs = [
    {
      name: 'commonName',
      value: 'Ory Polis',
    },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    {
      name: 'basicConstraints',
      cA: false,
    },
    {
      name: 'keyUsage',
      keyCertSign: false,
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
    },
  ]);

  // self-sign certificate
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    publicKey: pki.certificateToPem(cert),
    privateKey: pki.privateKeyToPem(keys.privateKey),
  };
};

export const getDefaultCertificate = async (): Promise<{ publicKey: string; privateKey: string }> => {
  if (cachedCertificate && !(await isCertificateExpired(cachedCertificate.publicKey))) {
    return cachedCertificate;
  }

  if (!certificateStore) {
    throw new Error('Certificate store not initialized');
  }

  if (!jacksonOption) {
    throw new Error('Jackson option not initialized');
  }

  // If the user has provided a certificate, use that instead of the default.
  // We expect the developer to provide base64 encoded keys, so we need to decode them.
  if (jacksonOption.certs?.privateKey && jacksonOption.certs?.publicKey) {
    cachedCertificate = {
      publicKey: Buffer.from(jacksonOption.certs.publicKey, 'base64').toString('utf-8'),
      privateKey: Buffer.from(jacksonOption.certs.privateKey, 'base64').toString('utf-8'),
    };

    return cachedCertificate;
  }

  // Otherwise, use the default certificate.
  cachedCertificate = await certificateStore.get('default');

  // If certificate is expired let it drop through so it creates a new cert
  if (cachedCertificate && !(await isCertificateExpired(cachedCertificate.publicKey))) {
    return cachedCertificate;
  }

  // If default certificate is not found or has expired, create one and store it.
  cachedCertificate = generateCertificate();

  await certificateStore.put('default', cachedCertificate);

  return cachedCertificate;
};

const isCertificateExpired = async (publicKey: string) => {
  const { validTo } = new crypto.X509Certificate(publicKey);

  return !(validTo !== 'Bad time value' && new Date(validTo) > new Date());
};
