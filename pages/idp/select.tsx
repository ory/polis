/* eslint-disable @next/next/no-img-element */
import { useEffect, useRef, useState } from 'react';
import getRawBody from 'raw-body';
import { useRouter } from 'next/router';
import { useTranslation } from 'next-i18next';
import type { OIDCSSORecord, ProductConfig, SAMLSSORecord } from '@boxyhq/saml-jackson';
import type { InferGetServerSidePropsType } from 'next';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import jackson from '@lib/jackson';
import Head from 'next/head';
import { hexToOklch } from '@lib/color';
import { PoweredBy } from '@components/ProtectedBy';
import { getPortalBranding, getProductBranding } from '@ee/branding/utils';
import { boxyhqHosted } from '@lib/env';
import { createGlobalStyle } from 'styled-components';

const GlobalStyle = createGlobalStyle<{ primaryColor: string | null }>`
  :root {
    --p: ${(props) => props.primaryColor || 'initial'};
  }
`;

interface Connection {
  name: string;
  product: string;
  clientID: string;
  sortOrder: number | null;
  deactivated: boolean;
}

export default function ChooseIdPConnection({
  connections,
  SAMLResponse,
  authFlow,
  branding,
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  const { t } = useTranslation('common');

  const primaryColor = hexToOklch(branding.primaryColor);
  const title = authFlow === 'sp-initiated' ? t('select_an_idp') : t('select_an_app');

  const selectors = {
    'sp-initiated': <IdpSelector connections={connections} />,
    'idp-initiated': <AppSelector connections={connections} SAMLResponse={SAMLResponse} />,
  };

  return (
    <div className='mx-auto my-28 w-[500px]'>
      <div className='mx-5 flex flex-col space-y-10 rounded border border-gray-300 p-10'>
        <Head>
          <title>{`${title} - ${branding.companyName}`}</title>
          {branding?.faviconUrl && <link rel='icon' href={branding.faviconUrl} />}
        </Head>

        <GlobalStyle primaryColor={primaryColor} />

        {branding?.logoUrl && (
          <div className='flex justify-center'>
            <img src={branding.logoUrl} alt={branding.companyName} className='max-h-14' />
          </div>
        )}

        {authFlow in selectors ? (
          selectors[authFlow]
        ) : (
          <p className='text-center text-sm text-slate-600'>{t('invalid_request_try_again')}</p>
        )}
      </div>
      <div className='my-4'>
        <PoweredBy />
      </div>
    </div>
  );
}

const IdpSelector = ({ connections }: { connections: Connection[] }) => {
  const router = useRouter();
  const { t } = useTranslation('common');

  // SP initiated SSO: Redirect to the same path with idp_hint set to the selected connection clientID
  const connectionSelected = (clientID: string) => {
    return router.push(`${router.asPath}&idp_hint=${clientID}`);
  };

  return (
    <>
      <h3 className='text-center text-xl font-bold'>{t('select_an_idp')}</h3>
      <ul className='flex flex-col space-y-5'>
        {connections.map((connection) => {
          return (
            <li key={connection.clientID} className='rounded bg-gray-100'>
              <button
                type='button'
                className='w-full'
                onClick={() => {
                  connectionSelected(connection.clientID);
                }}>
                <div className='flex items-center gap-2 px-3 py-3'>
                  <div className='placeholder avatar'>
                    <div className='w-8 rounded-full bg-primary text-white'>
                      <span className='text-lg font-bold'>{connection.name.charAt(0).toUpperCase()}</span>
                    </div>
                  </div>
                  {connection.name}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
      <p className='text-center text-sm text-slate-600'>{t('choose_an_identity_provider_to_continue')}</p>
    </>
  );
};

const AppSelector = ({
  connections,
  SAMLResponse,
}: {
  connections: Connection[];
  SAMLResponse: string | null;
}) => {
  const { t } = useTranslation('common');
  const formRef = useRef<HTMLFormElement>(null);
  const [connection, setConnection] = useState<string | null>(null);

  // Warn the user if they refresh the page
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (!connection) {
        e.preventDefault();
        e.returnValue = '';
        return '';
      }
    };

    if (!connection) {
      window.addEventListener('beforeunload', handleBeforeUnload);
    }

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [connection]);

  // IdP initiated SSO: Submit the SAMLResponse and idp_hint to the SAML ACS endpoint
  const appSelected = (e: React.ChangeEvent<HTMLInputElement>) => {
    setConnection(e.target.value);
    formRef.current?.submit();
  };

  if (!SAMLResponse) {
    return <p className='text-center text-sm text-slate-600'>{t('no_saml_response_try_again')}</p>;
  }

  return (
    <>
      <h3 className='text-center text-xl font-bold'>{t('select_an_app')}</h3>
      <form method='POST' action='/api/oauth/saml' ref={formRef}>
        <input type='hidden' name='SAMLResponse' value={SAMLResponse} />
        <ul className='flex flex-col space-y-5'>
          {connections.map((connection) => {
            return (
              <li key={connection.clientID} className='rounded bg-gray-100'>
                <div className='flex items-center gap-2 px-3 py-3'>
                  <input
                    type='radio'
                    name='idp_hint'
                    className='radio'
                    value={connection.clientID}
                    onChange={appSelected}
                    id={connection.clientID}
                  />
                  <label htmlFor={connection.clientID}>{connection.product}</label>
                </div>
              </li>
            );
          })}
        </ul>
      </form>
      <p className='text-center text-sm text-slate-600'>{t('choose_an_app_to_continue')}</p>
    </>
  );
};

export const getServerSideProps = async ({ query, locale, req }) => {
  const { connectionAPIController, identityFederationController, checkLicense, productController } =
    await jackson();

  const paramsToRelay = { ...query } as { [key: string]: string };

  const { authFlow, entityId, tenant, product, idp_hint, idFedAppId, fedType } = query as {
    authFlow: 'sp-initiated' | 'idp-initiated';
    tenant?: string;
    product?: string;
    idp_hint?: string;
    entityId?: string;
    idFedAppId?: string;
    fedType?: string;
  };

  if (!['sp-initiated', 'idp-initiated'].includes(authFlow)) {
    return {
      notFound: true,
    };
  }

  // The user has selected an IdP to continue with
  if (idp_hint) {
    const params = new URLSearchParams(paramsToRelay);
    const destination =
      idFedAppId && fedType !== 'oidc'
        ? `/api/identity-federation/sso?${params}`
        : `/api/oauth/authorize?${params}`;

    return {
      redirect: {
        destination,
        permanent: false,
      },
    };
  }

  const identityFederationApp = idFedAppId
    ? await identityFederationController.app.get({ id: idFedAppId })
    : null;

  if (idFedAppId && !identityFederationApp) {
    return {
      notFound: true,
    };
  }

  // Otherwise, show the list of IdPs
  let connections: (OIDCSSORecord | SAMLSSORecord)[] = [];

  if (identityFederationApp) {
    const tenants = identityFederationApp?.tenants || [identityFederationApp.tenant];
    const { product } = identityFederationApp;

    connections = await connectionAPIController.getConnections({ tenant: tenants, product, sort: true });
  } else if (tenant && product) {
    connections = await connectionAPIController.getConnections({ tenant, product, sort: true });
  } else if (entityId) {
    connections = await connectionAPIController.getConnections({ entityId: decodeURIComponent(entityId) });
  }

  // Get the branding to use for the IdP selector screen
  let branding = boxyhqHosted && product ? await getProductBranding(product) : await getPortalBranding();

  // For SAML federated requests, use the branding from the SAML federated app
  if (identityFederationApp && (await checkLicense())) {
    branding = {
      logoUrl: identityFederationApp?.logoUrl || branding.logoUrl,
      primaryColor: identityFederationApp?.primaryColor || branding.primaryColor,
      faviconUrl: identityFederationApp?.faviconUrl || branding.faviconUrl,
      companyName: identityFederationApp?.name || branding.companyName,
    };
  }

  let connectionsTransformed: Connection[] = connections.map((connection) => {
    const idpMetadata = 'idpMetadata' in connection ? connection.idpMetadata : undefined;
    const oidcProvider = 'oidcProvider' in connection ? connection.oidcProvider : undefined;

    const name =
      connection.name ||
      (idpMetadata ? idpMetadata.friendlyProviderName || idpMetadata.provider : `${oidcProvider?.provider}`);

    return {
      name,
      product: connection.product,
      clientID: connection.clientID,
      sortOrder: connection.sortOrder || null,
      deactivated: connection.deactivated || false,
    };
  });

  // Filter out connections that are not enabled
  connectionsTransformed = connectionsTransformed.filter((connection) => connection.deactivated !== true);

  // For idp-initiated flows, we need to parse the SAMLResponse from the request body and pass it to the component
  if (req.method == 'POST') {
    const body = await getRawBody(req);
    const params = new URLSearchParams(body.toString('utf-8'));

    const SAMLResponse = params.get('SAMLResponse');

    // SAMLResponse should exist with idp-initiated flow
    if (!SAMLResponse) {
      return {
        notFound: true,
      };
    }

    if (boxyhqHosted) {
      // Fetch products to display the product name instead of the product ID
      const products = (await Promise.allSettled(
        connectionsTransformed.map((connection) => productController.get(connection.product))
      )) as PromiseFulfilledResult<ProductConfig>[];

      connectionsTransformed = connectionsTransformed.map((connection, index) => {
        if (products[index].status === 'fulfilled') {
          return {
            ...connection,
            product: products[index].value.name || connection.product,
          };
        }

        return connection;
      });
    }

    return {
      props: {
        ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
        authFlow,
        SAMLResponse,
        connections: connectionsTransformed,
        branding,
      },
    };
  }

  return {
    props: {
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
      authFlow,
      SAMLResponse: null,
      connections: connectionsTransformed,
      branding,
    },
  };
};
