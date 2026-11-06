import crypto from 'crypto';

const transformBase64 = (input: string): string => {
  return input.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

export const encode = (code_challenge: string): string => {
  return transformBase64(crypto.createHash('sha256').update(code_challenge).digest('base64'));
};
