export const PageHeader = ({
  title,
  description,
  actions,
  className,
}: {
  title: string;
  description?: string;
  actions?: any;
  className?: string;
}) => {
  return (
    <div className={`flex flex-col ${className}`}>
      <div className='flex justify-between items-center'>
        <h2 className='text-emphasis text-xl font-semibold tracking-wide'>{title}</h2>
        {actions && <div className='flex gap-4'>{actions}</div>}
      </div>
      {description && <div className='text-gray-700 dark:text-white'>{description}</div>}
    </div>
  );
};
