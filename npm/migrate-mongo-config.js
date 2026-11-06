const config = {
  mongodb: {
    url: process.env.DB_URL || 'mongodb://localhost:27017/jackson',
    options: {
      useNewUrlParser: true, // removes a deprecation warning when connecting
      useUnifiedTopology: true, // removes a deprecating warning when connecting
      //   connectTimeoutMS: 3600000, // increase connection timeout to 1 hour
      //   socketTimeoutMS: 3600000, // increase socket timeout to 1 hour
    },
  },

  migrationsDir: 'migration/mongo',
  changelogCollectionName: 'changelog',
  migrationFileExtension: '.js',
  // Enable the algorithm to create a checksum of the file contents and use that in the comparison to determine
  // if the file should be run.  Requires that scripts are coded to be run multiple times.
  useFileHash: false,
  // Don't change this, unless you know what you're doing
  moduleSystem: 'commonjs',
};

module.exports = config;
