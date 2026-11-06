import { ButtonBase, type ButtonBaseProps } from './ButtonBase';

export const ButtonOutline = ({ children, ...other }: ButtonBaseProps) => {
  return (
    <ButtonBase variant='outline' {...other}>
      {children}
    </ButtonBase>
  );
};
