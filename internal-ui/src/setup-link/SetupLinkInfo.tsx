import { Button } from 'rsc-daisyui';
import { useTranslation } from 'next-i18next';

import { Card } from '../shared';
import type { SetupLink } from '../types';
import { InputWithCopyButton } from '../shared/InputWithCopyButton';

export const SetupLinkInfo = ({ setupLink, onClose }: { setupLink: SetupLink; onClose: () => void }) => {
  const { t } = useTranslation('common');

  return (
    <>
      <Card className='border-primary'>
        <Card.Body>
          <div>
            <InputWithCopyButton text={setupLink.url} label={t('bui-sl-share-info')} autofocus={true} />
          </div>
          <div>
            <Button size='sm' color='primary' onClick={onClose}>
              {t('bui-shared-close')}
            </Button>
          </div>
        </Card.Body>
      </Card>
    </>
  );
};
