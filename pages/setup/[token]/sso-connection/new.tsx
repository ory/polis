import fs from 'fs';
import path from 'path';
import Link from 'next/link';
import { useEffect } from 'react';
import remarkGfm from 'remark-gfm';
import mediumZoom from 'medium-zoom';
import { MDXRemote } from 'next-mdx-remote';
import { serialize } from 'next-mdx-remote/serialize';
import type { GetServerSidePropsContext, InferGetServerSidePropsType } from 'next';
import type { MDXRemoteSerializeResult } from 'next-mdx-remote';
import ArrowsRightLeftIcon from '@heroicons/react/24/outline/ArrowsRightLeftIcon';
import { serverSideTranslations } from 'next-i18next/serverSideTranslations';
import { useTranslation } from 'next-i18next';

import jackson from '@lib/jackson';
import { jacksonOptions } from '@lib/env';
import { identityProviders } from '@lib/constants';
import Footer from '@components/setup-link-instructions/Footer';
import NextButton from '@components/setup-link-instructions/NextButton';
import { InputWithCopyButton } from '@boxyhq/internal-ui';
import PreviousButton from '@components/setup-link-instructions/PreviousButton';
import CreateSSOConnection from '@components/setup-link-instructions/CreateSSOConnection';
import SelectIdentityProviders from '@components/setup-link-instructions/SelectIdentityProviders';
import StepProgressBar from '@components/setup-link/StepProgressBar';

type NewConnectionProps = InferGetServerSidePropsType<typeof getServerSideProps>;

const AdvancedSPConfigLink = () => {
  const { t } = useTranslation('common');

  return (
    <div className='py-2'>
      <Link href='/.well-known/saml-configuration' target='_blank' className='underline-offset-4'>
        <span className='text-xs'>{t('advanced_sp_saml_configuration')}</span>
      </Link>
    </div>
  );
};

const components = {
  Footer,
  NextButton,
  PreviousButton,
  InputWithCopyButton,
  CreateSSOConnection,
  AdvancedSPConfigLink,
};

const proseClassNames = [
  'prose',
  'prose-sm',
  'prose-h2:text-lg',
  'prose-h2:text-slate-700',
  'prose-h2:font-semibold',
  'prose-p:text-base',
  'prose-img:rounded',
  'prose-img:h-96',
  'prose-img:w-full',
  'prose-table:table',
  'prose-table:border',
  'prose-a:text-sm',
];

const findIdp = (idp: string) => {
  return identityProviders.find((provider) => provider.id === idp);
};

const NewConnection = ({
  step,
  idp,
  setupLinkToken,
  idpEntityId,
  source,
  spConfig,
  spMetadataUrl,
  publicCertUrl,
  oidcCallbackUrl,
}: NewConnectionProps) => {
  const { t } = useTranslation('common');

  const linkSelectIdp = { pathname: '/setup/[token]/sso-connection/new', query: { token: setupLinkToken } };

  const scope = {
    idpEntityId,
    spConfig,
    setupLinkToken,
    spMetadataUrl,
    publicCertUrl,
    oidcCallbackUrl,
  };

  let heading = '';
  let progress = 0;

  // Add zoom to images
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const zoom = mediumZoom('img', {
      scrollOffset: 0,
      margin: 50,
    });

    return () => {
      zoom.detach();
    };
  }, [step]);

  if (source && idp && step) {
    const selectedIdP = findIdp(idp);

    if (!selectedIdP) {
      throw new Error('Identity Provider not found');
    }

    progress = (100 / selectedIdP.stepCount) * parseInt(step);
    heading = t('configure_identity_provider', { provider: selectedIdP.name });
  } else {
    heading = t('select_identity_provider');
  }

  const getStepLabels = (provider) => {
    if (!provider) return [];
    return provider.steps;
  };

  return (
    <>
      <div className='flex flex-row gap-8 w-full'>
        <div className='w-64 py-6'>
          {source ? (
            <>
              {idp && (
                <StepProgressBar
                  currentStep={parseInt(step as string) - 1}
                  totalSteps={findIdp(idp)?.stepCount || 1}
                  steps={getStepLabels(findIdp(idp))}
                />
              )}
            </>
          ) : (
            <StepProgressBar
              currentStep={0}
              totalSteps={2}
              steps={['Select Provider', 'Create Application']}
            />
          )}
        </div>

        <div className='flex-1'>
          <div className='flex flex-col space-y-4 pb-6'>
            <div className='flex justify-between items-center'>
              <h1 className='text-xl font-normal'>{heading}</h1>
              {source && (
                <Link className='btn btn-xs h-0' href={linkSelectIdp}>
                  <ArrowsRightLeftIcon className='w-5 h-5' />
                  {t('change_identity_provider')}
                </Link>
              )}
            </div>
            {source && (
              <>
                <progress className='progress progress-primary w-full' value={progress} max={100} />
              </>
            )}
          </div>

          <article className={`${proseClassNames.join(' ')} max-w-4xl`}>
            {source ? (
              <MDXRemote {...source} components={components} scope={scope} />
            ) : (
              <SelectIdentityProviders />
            )}
          </article>
        </div>
      </div>
    </>
  );
};

export async function getServerSideProps({ locale, query }: GetServerSidePropsContext) {
  const { spConfig, setupLinkController, connectionAPIController } = await jackson();

  const { idp, step, token } = query as { idp: string; step: string; token: string };

  // Validate IDP and step
  let stepNumber;
  if (idp) {
    const provider = identityProviders.find((p) => p.id === idp);
    if (!provider) {
      return {
        redirect: {
          destination: `/setup/${token}/sso-connection/new`,
        },
      };
    }

    if (step) {
      stepNumber = parseInt(step, 10);

      if (isNaN(stepNumber) || stepNumber < 1 || stepNumber > provider.stepCount) {
        return {
          redirect: {
            destination: `/setup/${token}/sso-connection/new`,
          },
        };
      }
    }
  }

  const { tenant, product } = await setupLinkController.getByToken(token);
  const idpEntityId = connectionAPIController.getIDPEntityID({
    tenant,
    product,
  });

  let mdxSource: MDXRemoteSerializeResult<Record<string, unknown>> | null = null;

  // Read the MDX file based on the idp and stepNumber
  if (idp && stepNumber) {
    try {
      const mdxDirectory = path.join(process.cwd(), `components/setup-link-instructions/${idp}`);
      const source = fs.readFileSync(`${mdxDirectory}/${stepNumber}.mdx`, 'utf8');
      mdxSource = await serialize(source, {
        mdxOptions: { remarkPlugins: [remarkGfm] },
        blockJS: false,
      });
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err: any) {
      return {
        redirect: {
          destination: `/setup/${token}/sso-connection/new`,
        },
      };
    }
  }

  return {
    props: {
      idp: idp || null,
      step: step || null,
      setupLinkToken: token,
      idpEntityId,
      source: mdxSource,
      spConfig: await spConfig.get(),
      spMetadataUrl: `${jacksonOptions.externalUrl}/.well-known/sp-metadata`,
      publicCertUrl: `${jacksonOptions.externalUrl}/.well-known/saml.cer`,
      oidcCallbackUrl: `${jacksonOptions.externalUrl}${jacksonOptions.oidcPath}`,
      ...(locale ? await serverSideTranslations(locale, ['common']) : {}),
    },
  };
}

export default NewConnection;
