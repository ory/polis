import type { JacksonOption } from '../typings';

import saml20 from '@boxyhq/saml20';
import { getDefaultCertificate } from '../saml/x509';

// Service Provider SSO Configuration
export class SPSSOConfig {
  constructor(private opts: JacksonOption) {}

  private get acsUrl(): string {
    return this.opts.acsUrl as string;
  }

  private get entityId(): string {
    return `${this.opts.samlAudience}`;
  }

  private get responseSigned(): string {
    return 'Signed';
  }

  private get assertionSignature(): string {
    return 'Signed';
  }

  private get signatureAlgorithm(): string {
    return 'RSA-SHA256';
  }

  public get oidcRedirectURI(): string {
    return `${this.opts.externalUrl}${this.opts.oidcPath}`;
  }

  public async get(): Promise<{
    acsUrl: string;
    entityId: string;
    response: string;
    assertionSignature: string;
    signatureAlgorithm: string;
    publicKey: string;
    publicKeyString: string;
  }> {
    const cert = await getDefaultCertificate();

    return {
      acsUrl: this.acsUrl,
      entityId: this.entityId,
      response: this.responseSigned,
      assertionSignature: this.assertionSignature,
      signatureAlgorithm: this.signatureAlgorithm,
      publicKey: cert.publicKey,
      publicKeyString: saml20.stripCertHeaderAndFooter(cert.publicKey),
    };
  }

  public async toXMLMetadata(
    encryption = false,
    entityIdOverride?: string,
    acsUrlOverride?: string
  ): Promise<string> {
    const { entityId, acsUrl, publicKeyString } = await this.get();

    return saml20.createSPMetadataXML({
      entityId: entityIdOverride ? entityIdOverride : entityId,
      acsUrl: acsUrlOverride ? acsUrlOverride : acsUrl,
      publicKeyString,
      encryption,
    });
  }
}
