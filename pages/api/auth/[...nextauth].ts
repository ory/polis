import crypto from 'crypto';
import Adapter from '@lib/nextAuthAdapter';
import NextAuth from 'next-auth';
import EmailProvider from 'next-auth/providers/email';
import CredentialsProvider from 'next-auth/providers/credentials';
import BoxyHQSAMLProvider from 'next-auth/providers/boxyhq-saml';
import jackson from '@lib/jackson';
import { validateEmailWithACL } from '@lib/utils';
import { jacksonOptions as env } from '@lib/env';
import { sessionName } from '@lib/constants';

export default NextAuth({
  theme: {
    colorScheme: 'light',
  },
  providers: [
    BoxyHQSAMLProvider({
      authorization: { params: { scope: '' } },
      issuer: env.externalUrl,
      clientId: 'dummy',
      clientSecret: 'dummy',
      httpOptions: {
        timeout: 30000,
      },
      allowDangerousEmailAccountLinking: true,
    }),
    CredentialsProvider({
      id: 'boxyhq-saml-idplogin',
      // The name to display on the sign in form (e.g. 'Sign in with...')
      name: 'SAML IdP Login',
      // The credentials is used to generate a suitable form on the sign in page.
      // You can specify whatever fields you are expecting to be submitted.
      // e.g. domain, username, password, 2FA token, etc.
      // You can pass any HTML attribute to the <input> tag through the object.
      credentials: {
        code: {},
      },
      async authorize(credentials) {
        const { code } = credentials || {};
        if (!code) {
          return null;
        }
        const { oauthController } = await jackson();

        // Fetch access token
        const { access_token } = await oauthController.token({
          code,
          grant_type: 'authorization_code',
          redirect_uri: process.env.NEXTAUTH_URL || '',
          client_id: 'dummy',
          client_secret: process.env.CLIENT_SECRET_VERIFIER || '',
        });

        if (!access_token) {
          return null;
        }
        // Fetch user info
        const userInfo = await oauthController.userInfo(access_token);

        if (!userInfo) {
          return null;
        }

        if (userInfo?.id && userInfo?.email) {
          return {
            id: userInfo.id,
            email: userInfo.email,
            name: [userInfo.firstName, userInfo.lastName].filter(Boolean).join(' '),
            image: null,
          };
        }
        return null;
      },
    }),
    EmailProvider({
      server: {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      },
      from: process.env.SMTP_FROM,
    }),
    CredentialsProvider({
      credentials: {
        email: {},
        password: {},
      },
      async authorize(credentials) {
        if (!credentials) {
          return null;
        }

        const { email, password } = credentials;

        if (!email || !password) {
          return null;
        }

        const adminCredentials = process.env.NEXTAUTH_ADMIN_CREDENTIALS;

        if (!adminCredentials) {
          throw Error(
            'No admin credentials found. Please set NEXTAUTH_ADMIN_CREDENTIALS in your environment variables'
          );
        }

        // Find the admin credentials that match the email and password
        const adminCredentialsMatch = adminCredentials.split(',').find((credential) => {
          const [adminEmail, adminPassword] = credential.split(':');
          try {
            return (
              crypto.timingSafeEqual(Buffer.from(adminEmail), Buffer.from(email)) &&
              crypto.timingSafeEqual(Buffer.from(adminPassword), Buffer.from(password))
            );
          } catch {
            return false;
          }
        });

        // No match found
        if (!adminCredentialsMatch) {
          throw Error('Invalid email or password provided.');
        }

        return {
          id: Buffer.from(email).toString('base64'),
          name: email.split('@')[0],
          email,
        };
      },
    }),
  ],
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60,
  },
  jwt: {
    maxAge: 60 * 60 * 24 * 30,
  },
  cookies: {
    sessionToken: {
      name: sessionName,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: !(process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test'),
      },
    },
  },
  callbacks: {
    async signIn({ user, account }): Promise<boolean> {
      if (!user.email) {
        return false;
      }

      // Bypass ACL for credentials and boxyhq-saml (including IdP login)
      if (
        account?.provider === 'credentials' ||
        account?.provider === 'boxyhq-saml' ||
        account?.provider === 'boxyhq-saml-idplogin'
      ) {
        return true;
      }

      return validateEmailWithACL(user.email);
    },
  },
  pages: {
    signIn: '/admin/auth/login',
  },
  adapter: Adapter() as any,
});
