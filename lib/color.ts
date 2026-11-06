import chroma from 'chroma-js';

export const hexToOklch = (hexColor: string) => {
  const [l, c, h] = chroma(hexColor).oklch();
  return [l, c, h].join(' ');
};
