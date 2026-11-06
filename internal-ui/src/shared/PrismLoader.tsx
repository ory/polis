import { useEffect } from 'react';
import Prism from 'prismjs';
import 'prismjs/themes/prism-okaidia.css';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-typescript';
// import 'prismjs/components/prism-shell';
import 'prismjs/components/prism-json';
// import 'prismjs/components/prism-xml';

export function PrismLoader() {
  useEffect(() => {
    Prism.highlightAll();
  }, []);
  return <div className='hidden'></div>;
}
