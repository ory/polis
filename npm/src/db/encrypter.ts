import crypto from 'crypto';
import { Encrypted, EncryptionKey } from '../typings';

const ALGO = 'aes-256-gcm';
const BLOCK_SIZE = 12; // 96 bit

export const encrypt = (text: string, key: EncryptionKey): Encrypted => {
  const iv = crypto.randomBytes(BLOCK_SIZE);
  const cipher = crypto.createCipheriv(ALGO, key, iv);

  let ciphertext = cipher.update(text, 'utf8', 'base64');
  ciphertext += cipher.final('base64');

  return {
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    value: ciphertext,
  };
};

export const decrypt = (ciphertext: string, iv: string, tag: string, key: EncryptionKey): string => {
  const decipher = crypto.createDecipheriv(ALGO, key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));

  let cleartext = decipher.update(ciphertext, 'base64', 'utf8');
  cleartext += decipher.final('utf8');

  return cleartext;
};
