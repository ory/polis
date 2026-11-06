import { useContext } from 'react';
import { BUIContext } from '../provider';

export const useRouter = () => {
  const { router } = useContext(BUIContext);
  return { router };
};
