import { Card, Button } from 'rsc-daisyui';

export const DeleteCard = ({
  title,
  description,
  buttonLabel,
  onClick,
}: {
  title: string;
  description: string;
  buttonLabel: string;
  onClick: () => void;
}) => {
  return (
    <Card className='border-red-400'>
      <Card.Body className='p-6'>
        <div className='flex justify-between items-center gap-2'>
          <div className='flex flex-col gap-1'>
            <h6 className='text-lg font-medium'>{title}</h6>
            <p className='text-sm text-gray-500'>{description}</p>
          </div>
          <div>
            <Button color='warning' className='btn btn-md btn-error text-white' onClick={onClick}>
              {buttonLabel}
            </Button>
          </div>
        </div>
      </Card.Body>
    </Card>
  );
};
