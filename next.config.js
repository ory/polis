const path = require('path');
const { i18n } = require('./next-i18next.config');
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
});

/** @type {import('next').NextConfig} */

module.exports = withBundleAnalyzer({
  outputFileTracingRoot: path.join(__dirname),
  productionBrowserSourceMaps: true,
  reactStrictMode: true,
  i18n,
  output: 'standalone',
  webpack: (config, { dev, webpack, isServer }) => {
    // Enable source maps in development mode and for server-side rendering
    if (!dev && isServer) {
      config.devtool = 'source-map';
    }

    if (isServer) {
      // Module not found
      config.plugins.push(
        new webpack.IgnorePlugin({
          resourceRegExp:
            /(^@google-cloud\/spanner|^@mongodb-js\/zstd|^aws-crt|^aws4$|^pg-native$|^mongodb-client-encryption$|^@sap\/hana-client$|^@sap\/hana-client\/extension\/Stream$|^snappy$|^react-native-sqlite-storage$|^bson-ext$|^cardinal$|^kerberos$|^hdb-pool$|^sql.js$|^sqlite3$|^ioredis$|^typeorm-aurora-data-api-driver$|^pg-query-stream$|^oracledb$|^mysql$|^snappy\/package\.json$|^cloudflare:sockets$)/,
        })
      );
    }

    config.module = {
      ...config.module,
      exprContextCritical: false,
    };

    return config;
  },
  rewrites: async () => {
    return [
      {
        source: '/.well-known/saml.cer',
        destination: '/api/well-known/saml.cer',
      },
      {
        source: '/.well-known/openid-configuration',
        destination: '/api/well-known/openid-configuration',
      },
      {
        source: '/.well-known/oidc-configuration',
        destination: '/well-known/oidc-configuration',
      },
      {
        source: '/.well-known/sp-metadata',
        destination: '/api/well-known/sp-metadata',
      },
      {
        source: '/.well-known/idp-metadata',
        destination: '/api/well-known/idp-metadata',
      },
      {
        source: '/.well-known/saml-configuration',
        destination: '/well-known/saml-configuration',
      },
      {
        source: '/.well-known/idp-configuration',
        destination: '/well-known/idp-configuration',
      },
      {
        source: '/oauth/jwks',
        destination: '/api/oauth/jwks',
      },
      {
        source: '/admin/directory-sync/setup-link',
        destination: '/admin/setup-link',
      },
      {
        source: '/admin/sso-connection/setup-link',
        destination: '/admin/setup-link',
      },
      {
        source: '/admin/sso-connection/setup-link/new',
        destination: '/admin/setup-link/new',
      },
      {
        source: '/admin/directory-sync/setup-link/new',
        destination: '/admin/setup-link/new',
      },
      {
        source: '/.well-known',
        destination: '/well-known',
      },
      {
        source: '/admin/settings',
        destination: '/admin/settings/sso-connection',
      },
      {
        source: '/api/v1/connections/:path*',
        destination: '/api/v1/sso/:path*',
      },
      {
        source: '/api/v1/directory-sync/:path*',
        destination: '/api/v1/dsync/:path*',
      },
      {
        source: '/api/v1/saml-traces/:path*',
        destination: '/api/v1/sso-traces/:path*',
      },
      {
        source: '/api/v1/federated-saml/:path*',
        destination: '/api/v1/identity-federation/:path*',
      },
    ];
  },
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '*',
      },
    ],
  },
  async headers() {
    return [
      {
        source: '/(.*?)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains;',
          },
          {
            key: 'X-Frame-Options',
            value: 'SAMEORIGIN',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
        ],
      },
    ];
  },
});
