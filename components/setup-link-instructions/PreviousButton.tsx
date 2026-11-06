import { useRouter } from 'next/router';
import { useTranslation } from 'next-i18next';
import { ButtonOutline } from '@boxyhq/internal-ui';

const PreviousButton = () => {
  const router = useRouter();
  const { t } = useTranslation('common');

  const onClick = () => {
    const { idp, step, token } = router.query as { idp: string; step: string; token: string };

    router.push({
      pathname: router.pathname,
      query: {
        idp,
        step: parseInt(step) - 1,
        token,
      },
    });
  };

  return (
    <div>
      <ButtonOutline onClick={onClick}>{t('previous_step')}</ButtonOutline>
    </div>
  );
};

export default PreviousButton;
