import { ButtonBase, type ButtonBaseProps } from './ButtonBase';

export const ButtonPrimary = ({ children, ...other }: ButtonBaseProps) => {
  return (
    <ButtonBase color='primary' {...other}>
      {children}
    </ButtonBase>
  );
};
