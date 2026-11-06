export function normalizeBooleanParam(param) {
  if (param === 'false' || param === false) {
    return false;
  }

  return true;
}
