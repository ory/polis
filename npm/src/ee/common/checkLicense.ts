import { JacksonError } from '../../controller/error';

const checkLicense = async (license: string | undefined): Promise<boolean> => {
  if (!license) {
    return false;
  }

  return license === 'dummy-license';
};

export const throwIfInvalidLicense = async (license: string | undefined): Promise<void> => {
  if (!(await checkLicense(license))) {
    throw new JacksonError(
      'Enterprise License not found. This is an enterprise feature, please add a valid license to use this feature.',
      403
    );
  }
};

export default checkLicense;
