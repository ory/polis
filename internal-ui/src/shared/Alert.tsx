import { ReactNode } from 'react';

type AlertType = 'error' | 'success' | 'warning';

const variants = {
  error: 'alert-error',
  success: 'alert-success',
  warning: 'alert-warning',
} as const;

export const Alert = ({
  variant,
  children,
  className,
}: {
  variant: AlertType;
  children: ReactNode;
  className?: string;
}) => {
  return (
    <div role='alert' className={`rounded alert ${className} ${variants[variant]}`}>
      <span>{children}</span>
    </div>
  );
};
