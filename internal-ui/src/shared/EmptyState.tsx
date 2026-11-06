import InformationCircleIcon from '@heroicons/react/24/outline/InformationCircleIcon';

export const EmptyState = ({ title, description }: { title: string; description?: string | null }) => {
  return (
    <div className='my-2 flex w-full flex-col items-center justify-center rounded lg:p-20 border gap-2 bg-white dark:bg-black h-80 border-slate-300 dark:border-white'>
      <InformationCircleIcon className='w-10 h-10' />
      <h3 className='text-semibold text-emphasis text-center text-lg'>{title}</h3>
      {description && <p className='text-sm text-center font-light leading-6'>{description}</p>}
    </div>
  );
};
