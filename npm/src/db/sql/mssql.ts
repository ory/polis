type Options = {
  [key: string]: any;
};

export const parseURL = (url?: string): any => {
  if (!url) {
    throw new Error('URL is required');
  }

  const parts = url.split('://');

  if (parts.length !== 2) {
    throw new Error('Invalid connection string');
  }

  //const scheme = parts[0];
  const connectionString = parts[1];

  const connParts = connectionString.split(';');

  if (connParts.length == 0) {
    throw new Error('Invalid connection string');
  }

  // sqlserver://[serverName[\instanceName][:portNumber]][;property=value[;property=value]]

  const hostPort = connParts[0];
  const hostPortParts = hostPort.split(':');
  const host = hostPortParts[0];
  const port = hostPortParts.length > 1 ? parseInt(hostPortParts[1], 10) : 1433;

  const options: Options = {};
  connParts.slice(1).map((p) => {
    const ps = p.split('=');
    options[ps[0]] = ps[1];
  });

  const username = options.username || options.user;
  const password = options.password || options.pass;
  const database = options.database;
  delete options.username;
  delete options.user;
  delete options.password;
  delete options.pass;
  delete options.database;

  options.encrypt = Boolean(options.encrypt || false);
  options.trustServerCertificate = Boolean(options.trustServerCertificate || false);

  return {
    host,
    port,
    database,
    username,
    password,
    options,
  };
};
