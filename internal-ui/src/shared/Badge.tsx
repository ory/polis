import classNames from 'classnames';
import { Badge as BaseBadge } from 'rsc-daisyui';

export interface BadgeBaseProps {
  children?: React.ReactNode;
  className?: string;
  [key: string]: any;
}

export const Badge = ({ children, className, ...props }: BadgeBaseProps) => {
  return (
    <>
      <BaseBadge {...props} className={classNames('rounded text-xs py-2 text-white', className)}>
        {children}
      </BaseBadge>
    </>
  );
};
