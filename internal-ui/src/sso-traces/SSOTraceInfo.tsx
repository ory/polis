import useSWR from 'swr';
import { useTranslation } from 'next-i18next';

import { fetcher } from '../utils';
import type { SSOTrace } from '../types';
import { Loading, Error, PageHeader, Badge, PrismLoader } from '../shared';
import { CopyToClipboardButton } from '../shared/InputWithCopyButton';
import { JSX } from 'react';

const ListItem = ({ term, value }: { term: string; value: string | JSX.Element | JSX.Element[] }) => (
  <div className='grid grid-cols-3 py-3'>
    <dt className='text-sm font-medium text-gray-500'>{term}</dt>
    <dd className='text-sm text-gray-900 overflow-auto col-span-2'>{value}</dd>
  </div>
);

export const SSOTraceInfo = ({ urls }: { urls: { getTraces: string } }) => {
  const { t } = useTranslation('common');
  const { data, isLoading, error } = useSWR<{ data: SSOTrace & { traceId: string } }>(
    urls.getTraces,
    fetcher
  );

  if (isLoading) {
    return <Loading />;
  }

  if (error) {
    return <Error message={error.message} />;
  }

  if (!data) {
    return null;
  }

  const trace = data.data;
  const assertionType = trace.context.samlResponse ? 'Response' : trace.context.samlRequest ? 'Request' : '-';

  let badgeText = '';
  if (trace.context.isOIDCFederated) {
    if (trace.context.requestedOIDCFlow) {
      badgeText = t('bui-shared-oidc-federation');
    } else {
      badgeText = t('bui-traces-oauth2-federation');
    }
  } else if (trace.context.isSAMLFederated) {
    badgeText = t('bui-traces-saml-federation');
    if (trace.context.oidcIdPRequest) {
      badgeText += ',' + t('bui-traces-oidc-third-party-login');
    }
  } else if (trace.context.isIdPFlow) {
    badgeText = t('bui-traces-idp-login');
  } else if (trace.context.requestedOIDCFlow) {
    badgeText = t('bui-shared-oidc');
  } else {
    badgeText = t('bui-traces-oauth2');
  }

  const badge = badgeText.split(',').map((text) => (
    <Badge
      key={text}
      color='primary'
      size='md'
      className='font-mono uppercase text-white last-of-type:ml-2'
      aria-label={t('bui-traces-sp-protocol')!}>
      {text}
    </Badge>
  ));

  return (
    <div className='space-y-3'>
      <PageHeader title={t('bui-traces-title')} />
      <dl className='divide-y'>
        <ListItem term={t('bui-traces-id')} value={trace.traceId} />

        <ListItem term={t('bui-traces-assertion-type')} value={assertionType} />

        <ListItem term={t('bui-traces-sp-protocol')} value={badge} />

        {typeof trace.timestamp === 'number' && (
          <ListItem term={t('bui-traces-timestamp')} value={new Date(trace.timestamp).toLocaleString()} />
        )}

        <ListItem term={t('bui-traces-error')} value={trace.error} />

        {trace.context.tenant && <ListItem term={t('bui-shared-tenant')} value={trace.context.tenant} />}

        {trace.context.product && <ListItem term={t('bui-shared-product')} value={trace.context.product} />}

        {trace.context.relayState && (
          <ListItem term={t('bui-traces-relay-state')} value={trace.context.relayState} />
        )}

        {trace.context.redirectUri && (
          <ListItem
            term={
              trace.context.isIdPFlow ? t('bui-traces-default-redirect-url') : t('bui-traces-redirect-uri')
            }
            value={trace.context.redirectUri}
          />
        )}

        {trace.context.clientID && (
          <ListItem term={t('bui-traces-sso-connection-client-id')} value={trace.context.clientID} />
        )}

        {trace.context.issuer && <ListItem term={t('bui-traces-issuer')} value={trace.context.issuer} />}

        {trace.context.acsUrl && <ListItem term={t('bui-shared-acs-url')} value={trace.context.acsUrl} />}

        {trace.context.oAuthStage && (
          <ListItem
            term={t('bui-traces-oauth-stage')}
            value={
              <Badge
                key={trace.context.oAuthStage}
                color='secondary'
                size='md'
                className='font-mono uppercase text-white last-of-type:ml-2'
                aria-label={t('bui-traces-sp-protocol')!}>
                {trace.context.oAuthStage}
              </Badge>
            }
          />
        )}

        {trace.context.entityId && (
          <ListItem term={t('bui-traces-entity-id')} value={trace.context.entityId} />
        )}

        {trace.context.providerName && (
          <ListItem term={t('bui-traces-provider')} value={trace.context.providerName} />
        )}

        {assertionType === 'Response' && trace.context.samlResponse && (
          <ListItem
            term={t('bui-traces-saml-response')}
            value={
              <>
                <CopyToClipboardButton text={trace.context.samlResponse}></CopyToClipboardButton>
                <pre className='language-xml'>
                  <code className='language-xml'>{trace.context.samlResponse}</code>
                </pre>
              </>
            }
          />
        )}

        {assertionType === 'Request' && trace.context.samlRequest && (
          <ListItem
            term={t('bui-traces-saml-request')}
            value={
              <>
                <CopyToClipboardButton text={trace.context.samlRequest}></CopyToClipboardButton>
                <pre className='language-xml'>
                  <code className='language-xml'>{trace.context.samlRequest}</code>
                </pre>
              </>
            }
          />
        )}

        {typeof trace.context.profile === 'object' && trace.context.profile && (
          <ListItem
            term={t('bui-traces-profile')}
            value={
              <pre className='language-json'>
                <code className='language-json'>{JSON.stringify(trace.context.profile)}</code>
              </pre>
            }
          />
        )}

        {trace.context.error_description && (
          <ListItem
            term={t('bui-traces-error-description-from-oidc-idp')}
            value={trace.context.error_description}
          />
        )}

        {trace.context.error_uri && (
          <ListItem term={t('bui-traces-error-uri')} value={trace.context.error_uri} />
        )}

        {trace.context.oidcTokenSet?.id_token && (
          <ListItem
            term={t('bui-traces-id-token-from-oidc-idp')}
            value={
              <>
                <CopyToClipboardButton text={trace.context.oidcTokenSet.id_token}></CopyToClipboardButton>
                <pre className='language-shell'>
                  <code className='language-shell'>{trace.context.oidcTokenSet.id_token}</code>
                </pre>
              </>
            }
          />
        )}

        {trace.context.oidcTokenSet?.access_token && (
          <ListItem
            term={t('bui-traces-access-token-from-oidc-idp')}
            value={
              <>
                <CopyToClipboardButton text={trace.context.oidcTokenSet.access_token}></CopyToClipboardButton>
                <pre className='language-shell'>
                  <code className='language-shell'>{trace.context.oidcTokenSet.access_token}</code>
                </pre>
              </>
            }
          />
        )}

        {trace.context.stack && (
          <ListItem
            term={t('bui-traces-stack-trace')}
            value={
              <pre className='language-shell'>
                <code className='language-shell'>{trace.context.stack}</code>
              </pre>
            }
          />
        )}

        {trace.context.session_state_from_op_error && (
          <ListItem
            term={t('bui-traces-session-state-from-oidc-idp')}
            value={trace.context.session_state_from_op_error}
          />
        )}

        {trace.context.scope_from_op_error && (
          <ListItem term={t('bui-traces-scope-from-op-error')} value={trace.context.scope_from_op_error} />
        )}

        {trace.context.oidcIdPRequest && (
          <ListItem
            term={t('bui-traces-oidc-third-party-login-params')}
            value={JSON.stringify(trace.context.oidcIdPRequest)}
          />
        )}
      </dl>
      <PrismLoader></PrismLoader>
    </div>
  );
};
