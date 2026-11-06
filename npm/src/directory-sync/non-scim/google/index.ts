import { GoogleAuth } from './oauth';
import { GoogleProvider } from './api';
import type { IDirectoryConfig, JacksonOption } from '../../../typings';

interface NewGoogleProviderParams {
  directories: IDirectoryConfig;
  opts: JacksonOption;
}

export const newGoogleProvider = (params: NewGoogleProviderParams) => {
  const { directories, opts } = params;

  return {
    directory: new GoogleProvider({ opts, directories }),
    oauth: new GoogleAuth({ opts, directories }),
  };
};
