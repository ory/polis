import NextButton from '@components/setup-link-instructions/NextButton';
import PreviousButton from '@components/setup-link-instructions/PreviousButton';

interface FooterProps {
  hasNext?: boolean;
}

const Footer = ({ hasNext = true }: FooterProps) => {
  return (
    <div className='flex justify-between items-center py-4'>
      <PreviousButton />
      {hasNext && <NextButton />}
    </div>
  );
};

export default Footer;
