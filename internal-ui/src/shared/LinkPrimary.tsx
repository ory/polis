import classNames from 'classnames';
import { LinkBase, type LinkBaseProps } from './LinkBase';

export const LinkPrimary = ({ children, className, ...others }: LinkBaseProps) => {
  return (
    <LinkBase className={classNames('btn-primary', className)} {...others}>
      {children}
    </LinkBase>
  );
};
