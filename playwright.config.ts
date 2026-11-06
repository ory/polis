import { PlaywrightTestConfig, devices } from '@playwright/test';
import path from 'path';

// Reference: https://playwright.dev/docs/test-configuration
const config: PlaywrightTestConfig = {
  workers: 1,
  globalSetup: require.resolve('./e2e/support/globalSetup'),
  // Timeout per test
  timeout: 100 * 1000,
  // Assertion timeout
  expect: {
    timeout: 10 * 1000,
  },
  // Test directory
  testDir: path.join(__dirname, 'e2e'),
  // If a test fails, retry it additional 3 times
  retries: 1,
  reporter: 'html',

  // Run your local dev server before starting the tests:
  // https://playwright.dev/docs/test-advanced#launching-a-development-web-server-during-the-tests
  webServer: {
    command: 'npm run start',
    port: 5225,
    timeout: 60 * 1000,
    reuseExistingServer: !process.env.CI,
    env: {
      DEBUG: 'pw:webserver',
      NEXTAUTH_ADMIN_CREDENTIALS: 'super@boxyhq.com:999login',
    },
  },

  use: {
    // Base URL for all tests
    baseURL: 'http://localhost:5225',

    // Retry a test if its failing with enabled tracing. This allows you to analyse the DOM, console logs, network traffic etc.
    // More information: https://playwright.dev/docs/trace-viewer
    trace: 'retain-on-first-failure',
    storageState: './e2e/state.json',
    headless: !!process.env.CI,

    // All available context options: https://playwright.dev/docs/api/class-browser#browser-new-context
    // contextOptions: {
    //   ignoreHTTPSErrors: true,
    // },
  },

  projects: [
    {
      name: 'Desktop Chrome',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: 'http://localhost:5225',
        storageState: './e2e/state.json',
        channel: 'chrome',
      },
    },
    // {
    //   name: 'Desktop Firefox',
    //   use: {
    //     ...devices['Desktop Firefox'],
    //   },
    // },
    // {
    //   name: 'Desktop Safari',
    //   use: {
    //     ...devices['Desktop Safari'],
    //   },
    // },
    // Test against mobile viewports.
    // {
    //   name: 'Mobile Chrome',
    //   use: {
    //     ...devices['Pixel 5'],
    //   },
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: devices['iPhone 12'],
    // },
  ],
};
export default config;
