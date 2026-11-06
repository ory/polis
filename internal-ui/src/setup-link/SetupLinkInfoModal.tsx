import { Button } from 'rsc-daisyui';
import { useTranslation } from 'next-i18next';

import { Modal } from '../shared';
import type { SetupLink } from '../types';
import { InputWithCopyButton } from '../shared/InputWithCopyButton';

export const SetupLinkInfoModal = ({
  setupLink,
  visible,
  onClose,
}: {
  setupLink: SetupLink;
  visible: boolean;
  onClose: () => void;
}) => {
  const { t } = useTranslation('common');

  const expiresAt = new Date(setupLink.validTill).toUTCString();
  const isExpired = new Date(setupLink.validTill) < new Date();

  return (
    <Modal visible={visible} title={`Setup Link for ${setupLink.tenant}`}>
      <div className='pt-3'>
        <InputWithCopyButton label={t('bui-sl-share-link-info')} text={setupLink.url} />
      </div>
      {!isExpired ? (
        <p className='text-sm text-gray-500 mt-3'>{t('bui-sl-link-expire-on', { expiresAt })}</p>
      ) : (
        <p className='text-sm text-red-500 mt-3'>{t('bui-sl-link-expired')}</p>
      )}
      <div className='modal-action'>
        <Button color='secondary' outline={true} type='button' size='md' onClick={() => onClose()}>
          {t('bui-shared-close')}
        </Button>
      </div>
    </Modal>
  );
};
