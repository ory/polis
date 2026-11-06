export const options = {
  extraHTTPHeaders: {
    Authorization: `Api-Key ${process.env.JACKSON_API_KEYS}`,
    'Content-Type': 'application/json',
  },
};
