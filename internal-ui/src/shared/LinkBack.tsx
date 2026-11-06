import ArrowLeftIcon from '@heroicons/react/24/outline/ArrowLeftIcon';
import { useTranslation } from 'next-i18next';
import { ButtonOutline } from './ButtonOutline';
import { LinkOutline } from './LinkOutline';

export const LinkBack = ({
  href,
  onClick,
  className,
}: {
  href?: string;
  onClick?: () => void;
  className?: string;
}) => {
  const { t } = useTranslation('common');

  if (href) {
    return (
      <LinkOutline href={href} Icon={ArrowLeftIcon} className={className}>
        {t('back')}
      </LinkOutline>
    );
  }

  if (onClick) {
    return (
      <ButtonOutline onClick={onClick} Icon={ArrowLeftIcon} className={className}>
        {t('back')}
      </ButtonOutline>
    );
  }

  return null;
};
