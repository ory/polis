import { ButtonBase, type ButtonBaseProps } from './ButtonBase';

export const ButtonDanger = ({ children, ...other }: ButtonBaseProps) => {
  return (
    <ButtonBase color='error' {...other}>
      {children}
    </ButtonBase>
  );
};
