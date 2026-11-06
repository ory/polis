import { useTranslation } from 'next-i18next';
import ArrowLeftIcon from '@heroicons/react/24/outline/ArrowLeftIcon';
import ArrowRightIcon from '@heroicons/react/24/outline/ArrowRightIcon';
import { ButtonOutline } from './ButtonOutline';

export const pageLimit = 50;

export const Pagination = ({
  itemsCount,
  offset,
  onPrevClick,
  onNextClick,
}: {
  itemsCount: number;
  offset: number;
  onPrevClick: () => void;
  onNextClick: () => void;
}) => {
  const { t } = useTranslation('common');

  // Hide pagination if there are no items to paginate.
  if ((itemsCount === 0 && offset === 0) || (itemsCount < pageLimit && offset === 0)) {
    return null;
  }

  const prevDisabled = offset === 0;
  const nextDisabled = itemsCount < pageLimit || itemsCount === 0;

  return (
    <div className='flex justify-center space-x-4 py-4'>
      <ButtonOutline
        className='btn-md'
        Icon={ArrowLeftIcon}
        aria-label={t('bui-shared-previous') as string}
        onClick={onPrevClick}
        disabled={prevDisabled}>
        {t('bui-shared-previous')}
      </ButtonOutline>
      <ButtonOutline
        className='btn-md'
        Icon={ArrowRightIcon}
        aria-label={t('bui-shared-next') as string}
        onClick={onNextClick}
        disabled={nextDisabled}>
        {t('bui-shared-next')}
      </ButtonOutline>
    </div>
  );
};
