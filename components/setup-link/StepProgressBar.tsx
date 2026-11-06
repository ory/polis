import React from 'react';

const StepProgressBar = ({ currentStep, totalSteps, steps }) => {
  return (
    <div className='w-full flex flex-col gap-2 mt-4 mb-6'>
      <div className='flex flex-col gap-4'>
        {Array.from({ length: totalSteps }, (_, index) => (
          <div key={index} className='flex items-center gap-4 p-2'>
            <div
              className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0
                ${index <= currentStep ? 'bg-primary text-white' : 'bg-gray-200 text-gray-600'}`}>
              {index + 1}
            </div>
            <span className={`text-sm ${index === currentStep ? 'font-medium' : 'text-gray-600'}`}>
              {steps[index]}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default StepProgressBar;
