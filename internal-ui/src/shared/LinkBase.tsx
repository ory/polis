import Link from 'next/link';
import classNames from 'classnames';

export interface LinkBaseProps {
  href: string;
  Icon?: any;
  children: React.ReactNode;
  className?: string;
  [key: string]: any;
}

export const LinkBase = ({ children, href, className, Icon, ...others }: LinkBaseProps) => {
  return (
    <Link href={href} className={classNames('btn', className)} {...others} passHref>
      {Icon && <Icon className='mr-1 h-4 w-4' aria-hidden />}
      {children}
    </Link>
  );
};
