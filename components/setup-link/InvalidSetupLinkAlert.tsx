import { useTranslation } from 'next-i18next';

const InvalidSetupLinkAlert = ({ message }: { message: string }) => {
  const { t } = useTranslation('common');

  return (
    <div className='flex flex-col gap-3 rounded border border-error p-4'>
      <h3 className='text-base font-medium'>{message}</h3>
      <p className='leading-6'>{t('invalid_setup_link_alert')}</p>
    </div>
  );
};

export default InvalidSetupLinkAlert;
