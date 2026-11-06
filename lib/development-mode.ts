import jackson from './jackson';
import { IndexNames } from 'npm/src/controller/utils';
import { jacksonOptions } from '@lib/env';

type Module = 'sso' | 'dsync' | 'identityFederation';

export const validateDevelopmentModeLimits = async (
  productId: string,
  type: Module,
  message: string = 'Maximum number of connections reached'
) => {
  if (productId && jacksonOptions.boxyhqHosted) {
    const {
      productController,
      connectionAPIController,
      directorySyncController,
      identityFederationController,
    } = await jackson();

    const getController = async (type: Module) => {
      switch (type) {
        case 'sso':
          return connectionAPIController;
        case 'dsync':
          return directorySyncController.directories;
        case 'identityFederation':
          return identityFederationController.app;
        default:
          return {
            getCount: () => null,
          };
      }
    };

    const product = await productController.get(productId);
    if (product?.development) {
      const controller = await getController(type);
      const count = await controller.getCount({
        name: IndexNames.Product,
        value: productId,
      });
      if (count) {
        if (count >= 3) {
          throw { message, statusCode: 400 };
        }
      }
    }
  }
};
