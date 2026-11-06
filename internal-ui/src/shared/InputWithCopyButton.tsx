import { useTranslation } from 'next-i18next';
import { copyToClipboard } from '../utils';
import { IconButton } from './IconButton';
import ClipboardDocumentIcon from '@heroicons/react/24/outline/ClipboardDocumentIcon';

export const CopyToClipboardButton = ({ text }: { text: string }) => {
  const { t } = useTranslation('common');

  return (
    <IconButton
      tooltip={t('bui-shared-copy')}
      Icon={ClipboardDocumentIcon}
      className='hover:text-primary'
      onClick={() => {
        copyToClipboard(text);
        // successToast(t('copied'));
      }}
    />
  );
};

export const InputWithCopyButton = ({
  text,
  label,
  autofocus = false,
}: {
  text: string;
  label: string;
  autofocus?: boolean;
}) => {
  const id = label.replace(/ /g, '');
  return (
    <>
      <div className='flex justify-between'>
        <label className='mb-2 block text-sm font-medium text-gray-900 dark:text-gray-300' htmlFor={id}>
          {label}
        </label>
        <CopyToClipboardButton text={text} />
      </div>
      <input
        id={id}
        type='text'
        defaultValue={text}
        key={text}
        readOnly
        className='input-bordered input w-full text-sm'
        autoFocus={autofocus}
      />
    </>
  );
};
