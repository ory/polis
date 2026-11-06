import React from 'react';
import { useState, useEffect } from 'react';

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
  const [open, setOpen] = useState(visible ? visible : false);

  useEffect(() => {
    setOpen(visible);
  }, [visible]);

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
