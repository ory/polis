import classNames from 'classnames';
import { Button } from 'rsc-daisyui';

export interface ButtonBaseProps {
  Icon?: any;
  children?: React.ReactNode;
  [key: string]: any;
}

export const ButtonBase = ({ Icon, children, ...others }: ButtonBaseProps) => {
  return (
    <Button {...others}>
      {Icon && <Icon className={classNames('h-4 w-4', children ? 'mr-1' : '')} aria-hidden />}
      {children}
    </Button>
  );
};
