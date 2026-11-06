import { type APIRequestContext, expect } from '@playwright/test';
import { OAuthReq } from 'npm/src';

// Make oauth autorize request
export const oauthAuthorize = async (request: APIRequestContext, data: OAuthReq, isFailure = false) => {
  try {
    const response = await request.post('/api/oauth/authorize', {
      data,
    });

    expect(response.ok()).toBe(true);
    if (!isFailure) {
      expect(response.status()).toBe(302);
    }
  } catch (ex: any) {
    if (isFailure) {
      expect(ex.message).toBeDefined();
    } else {
      throw ex;
    }
  }
};
