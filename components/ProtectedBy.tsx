import { useTranslation } from 'next-i18next';

export const PoweredBy = () => {
  const { t } = useTranslation('common');

  return (
    <p className='text-center text-xs text-gray-500 py-5'>
      <a href='https://www.ory.sh' target='_blank' rel='noopener noreferrer'>
        {t('ory_protected_by')}
      </a>
    </p>
  );
};
