import { useRouter } from 'next/router';
import { useTranslation } from 'next-i18next';
import { ButtonPrimary } from '@boxyhq/internal-ui';

const NextButton = () => {
  const router = useRouter();
  const { t } = useTranslation('common');

  const onClick = () => {
    const { idp, step, token } = router.query as { idp: string; step: string; token: string };

    router.push({
      pathname: router.pathname,
      query: {
        idp,
        step: parseInt(step) + 1,
        token,
      },
    });
  };

  return (
    <div>
      <ButtonPrimary onClick={onClick}>{t('next_step')}</ButtonPrimary>
    </div>
  );
};

export default NextButton;
