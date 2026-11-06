import { createContext } from 'react';
import type { NextRouter } from 'next/router';

export const BUIContext = createContext<{ router: NextRouter | null }>({ router: null });

export const BUIProvider = BUIContext.Provider;
