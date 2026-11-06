// global-setup.ts
import { chromium, FullConfig } from '@playwright/test';
import { IDENTIFIER, TOKEN } from './nextAuth.constants';

function streamToString(stream): Promise<string> {
  const chunks: any[] = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on('error', (err) => reject(err));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function globalSetup(config: FullConfig) {
  // Env init
  process.env.MOCKSAML_ORIGIN = process.env.CI ? 'http://localhost:4000' : 'https://mocksaml.com';
  // Magic Link Login
  const { baseURL, storageState } = config.projects[0].use;
  // Generate a link with email, unhashed token and callback url
  const params = new URLSearchParams({ callbackURL: baseURL || '', token: TOKEN, email: IDENTIFIER });
  const providerId = 'email';
  const MAGIC_LINK = `${baseURL}/api/auth/callback/${providerId}?${params}`;
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto(MAGIC_LINK);
  await page.context().storageState({ path: storageState as string });

  // Get MockSAML metadata
  await page.goto(process.env.MOCKSAML_ORIGIN);
  // Start waiting for download before clicking. Note no await.
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download Metadata' }).click();
  const download = await downloadPromise;
  const _stream = await download.createReadStream();
  const _metadata = await streamToString(_stream);
  process.env.MOCKSAML_METADATA = _metadata;

  await browser.close();
}

export default globalSetup;
