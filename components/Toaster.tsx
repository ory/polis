import { useState, useEffect, Dispatch, SetStateAction } from 'react';
import { Alert, Button, Toast } from 'rsc-daisyui';

type ToastItem = {
  text: string;
  status: 'success' | 'error';
};

let gSetToasts: Dispatch<SetStateAction<{ success?: ToastItem; error?: ToastItem }>> | null = null;
let successTimeoutId: ReturnType<typeof setTimeout> | null = null;

export const Toaster = () => {
  const [toasts, setToasts] = useState<{ success?: ToastItem; error?: ToastItem }>({});

  // Only assign once — in an effect, not during render
  useEffect(() => {
    gSetToasts = setToasts;
    return () => {
      gSetToasts = null; // clean up on unmount
    };
  }, []);

  return (
    <div className='App'>
      <Toast horizontal='end' vertical='bottom'>
        {[toasts.success, toasts.error].map((toast, index) => {
          if (!toast) return null;

          return (
            <Alert key={`toast-${index}`} color={toast.status} className='rounded py-3'>
              <h3>{toast.text}</h3>
              <Button
                ghost={true}
                onClick={() =>
                  setToasts({
                    success: toast.status === 'success' ? undefined : toasts.success,
                    error: toast.status === 'error' ? undefined : toasts.error,
                  })
                }>
                X
              </Button>
            </Alert>
          );
        })}
      </Toast>
    </div>
  );
};

export const successToast = (text: string) => {
  if (gSetToasts) {
    gSetToasts({ success: { text, status: 'success' } });
    if (successTimeoutId) clearTimeout(successTimeoutId);
    successTimeoutId = setTimeout(() => {
      if (gSetToasts) {
        gSetToasts((prev) => ({ ...prev, success: undefined }));
      }
    }, 10000);
  }
};

export const errorToast = (text: string) => {
  if (gSetToasts) {
    gSetToasts((prev) => ({ ...prev, error: { text, status: 'error' } }));
  }
};
