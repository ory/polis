import React from 'react';

export const Modal = ({
  visible,
  title,
  description,
  children,
}: {
  visible: boolean;
  title: string;
  description?: string;
  children?: React.ReactNode;
}) => {
  // The modal is fully controlled by the visible prop, so derive open during
  // render instead of mirroring it into state via an effect.
  const open = visible;

  return (
    <div className={`modal ${open ? 'modal-open' : ''}`}>
      <div className='modal-box'>
        <div className='flex flex-col gap-1'>
          <h3 className='text-lg font-bold'>{title}</h3>
          {description && <p className='text-sm'>{description}</p>}
          <div>{children}</div>
        </div>
      </div>
    </div>
  );
};
