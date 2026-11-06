import { JacksonError } from '../../controller/error';
import { throwIfInvalidLicense } from '../common/checkLicense';
import type { Storable, ProductConfig, JacksonOptionWithRequiredLogger } from '../../typings';

export class ProductController {
  private productStore: Storable;
  private opts: JacksonOptionWithRequiredLogger;

  constructor({ productStore, opts }: { productStore: Storable; opts: JacksonOptionWithRequiredLogger }) {
    this.productStore = productStore;
    this.opts = opts;
  }

  public async get(productId: string): Promise<ProductConfig> {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    const productConfig = (await this.productStore.get(productId)) as ProductConfig;

    // if (!productConfig) {
    //   this.opts.logger.error(`Product config not found for ${productId}`);
    // }

    return {
      ...productConfig,
      id: productId,
      name: productConfig?.name || null,
      teamId: productConfig?.teamId || null,
      teamName: productConfig?.teamName || null,
      logoUrl: productConfig?.logoUrl || null,
      faviconUrl: productConfig?.faviconUrl || null,
      companyName: productConfig?.companyName || null,
      primaryColor: productConfig?.primaryColor || '#4f39f6',
    };
  }

  public async upsert(params: Partial<ProductConfig> & { id: string }) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    if (!('id' in params)) {
      throw new JacksonError('Provide a product id', 400);
    }

    const productConfig = (await this.productStore.get(params.id)) as ProductConfig;

    const toUpdate = productConfig ? { ...productConfig, ...params } : params;

    await this.productStore.put(params.id, toUpdate);
  }

  public async delete(productId: string) {
    await throwIfInvalidLicense(this.opts.boxyhqLicenseKey);

    await this.productStore.delete(productId);
  }
}
