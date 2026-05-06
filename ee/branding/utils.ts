import jackson from '@lib/jackson';
import { polisHosted } from '@lib/env';
import { polisBranding } from 'internal-ui/src';

export const getPortalBranding = async () => {
  const { brandingController, checkLicense } = await jackson();

  // If the licence is not valid, return the default branding
  if (!(await checkLicense())) {
    return polisBranding;
  }

  const customBranding = await brandingController?.get();

  return {
    logoUrl: customBranding?.logoUrl || polisBranding.logoUrl,
    primaryColor: customBranding?.primaryColor || polisBranding.primaryColor,
    faviconUrl: customBranding?.faviconUrl || polisBranding.faviconUrl,
    companyName: customBranding?.companyName || polisBranding.companyName,
  };
};

/**
 * Get the branding for a specific product.
 * If the product does not have a custom branding, return the default branding
 * @param productId
 * @returns
 */
export const getProductBranding = async (productId: string) => {
  const { checkLicense, productController } = await jackson();

  if (!(await checkLicense())) {
    return polisBranding;
  }

  if (!polisHosted || !productId) {
    return polisBranding;
  }

  const productBranding = await productController?.get(productId);

  return {
    logoUrl: productBranding.logoUrl || polisBranding.logoUrl,
    faviconUrl: productBranding.faviconUrl || polisBranding.faviconUrl,
    companyName: productBranding.companyName || polisBranding.companyName,
    primaryColor: productBranding.primaryColor || polisBranding.primaryColor,
  };
};
