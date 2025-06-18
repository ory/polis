import { EmptyState } from '@boxyhq/internal-ui';

const LicenseRequired = () => {
  return (
    <EmptyState
      title='This is an Enterprise feature.'
      description="Please add a valid license to use this feature. If you don't have a license, please contact Ory support."
    />
  );
};

export default LicenseRequired;
