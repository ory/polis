const fs = require('fs');
const path = require('path');
const regExp = /\bt\('(.*?)'/gm;
const altRegExp = /\bi18nKey='(.*?)'/gm;
const exceptionList = ['client_error', 'server_error'];

const allStrings = {};

const localeFile = require('./locales/en/common.json');

const files = fs.readdirSync('./', { recursive: true, withFileTypes: true });

let error = false;

files.forEach((file) => {
  if (file.isDirectory()) {
    return;
  }
  if (file.parentPath?.includes('node_modules')) {
    return;
  }

  if (['.ts', '.tsx'].includes(path.extname(file.name).toLowerCase())) {
    const fileContent = fs.readFileSync(path.join(file.parentPath, file.name), 'utf8');

    (fileContent.match(regExp) || []).forEach((match) => {
      const id = match.replace("t('", '').replace("'", '');
      allStrings[id] = true;
      if (!localeFile[id]) {
        error = true;
        console.error(`Missing key: ${path.join(file.parentPath, file.name)} - ${id}`);
      }
    });

    (fileContent.match(altRegExp) || []).forEach((match) => {
      const id = match.replace("i18nKey='", '').replace("'", '');
      allStrings[id] = true;
      if (!localeFile[id]) {
        error = true;
        console.error(`Missing key: ${path.join(file.parentPath, file.name)} - ${id}`);
      }
    });
  }
});

Object.keys(localeFile).forEach((key) => {
  if (!allStrings[key] && !exceptionList.includes(key)) {
    error = true;
    console.error(`Unused key: ${key}`);
  }
});

if (error) {
  process.exit(1);
}
