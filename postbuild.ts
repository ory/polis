import path from 'node:path';
import { cpSync } from 'node:fs';

const folders = [
  { src: 'public', dst: path.join('.next', 'standalone', 'public') },
  { src: path.join('.next', 'static'), dst: path.join('.next', 'standalone', '.next', 'static') },
];

try {
  folders.forEach(({ src, dst }) => cpSync(src, dst, { recursive: true }));
  console.log(`copied public/static assets to standalone build`);
} catch (err) {
  console.error(`failed copying public/static assets to standalone build`, err);
}
