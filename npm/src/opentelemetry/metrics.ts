import { incrementCounter, observeGauge, type CounterOperationParams } from '@boxyhq/metrics';

const METER = 'jackson';

const counters = {
  createConnection: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.connection.create',
      counterOptions: { description: 'Number of IdP connection create requests' },
    }),
  getConnections: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.connection.get',
      counterOptions: { description: 'Number of IdP connections get requests' },
    }),
  deleteConnections: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.connection.delete',
      counterOptions: { description: 'Number of IdP connections delete requests' },
    }),
  oauthAuthorize: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.authorize',
      counterOptions: { description: 'Number of oauth authorize requests' },
    }),
  oauthAuthorizeError: (counterAttributes: CounterOperationParams['counterAttributes']) =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.authorize.error',
      counterOptions: { description: 'Number of errors in oauth authorize requests' },
      counterAttributes,
    }),
  oauthResponse: (counterAttributes: CounterOperationParams['counterAttributes']) =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.response',
      counterOptions: { description: 'Number of oauth response requests' },
      counterAttributes,
    }),
  oauthResponseError: (counterAttributes: CounterOperationParams['counterAttributes']) =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.response.error',
      counterOptions: { description: 'Number of errors in idp response path' },
      counterAttributes,
    }),
  oauthToken: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.token',
      counterOptions: { description: 'Number of oauth token requests' },
    }),
  oauthTokenError: (counterAttributes: CounterOperationParams['counterAttributes']) =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.token.error',
      counterOptions: { description: 'Number of errors in oauth token requests' },
      counterAttributes,
    }),
  oauthUserInfo: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.userinfo',
      counterOptions: { description: 'Number of oauth user info requests' },
    }),
  oauthUserInfoError: (counterAttributes: CounterOperationParams['counterAttributes']) =>
    incrementCounter({
      meter: METER,
      name: 'jackson.oauth.userinfo.error',
      counterOptions: { description: 'Number of errors in oauth user info requests' },
      counterAttributes,
    }),

  createDsyncConnection: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.dsync.connection.create',
      counterOptions: { description: 'Number of DSync connection create requests' },
    }),

  getDsyncConnections: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.dsync.connection.get',
      counterOptions: { description: 'Number of DSync connections get requests' },
    }),

  deleteDsyncConnections: () =>
    incrementCounter({
      meter: METER,
      name: 'jackson.dsync.connection.delete',
      counterOptions: { description: 'Number of DSync connections delete requests' },
    }),

  dsyncEventsBatchFailed: () => {
    incrementCounter({
      meter: METER,
      name: 'jackson.dsync.events_batch.failed',
      counterOptions: { description: 'Indicate that a batch of dsync events failed' },
    });
  },
  idfedAuthorize: (counterAttributes: CounterOperationParams['counterAttributes']) => {
    incrementCounter({
      meter: METER,
      name: 'jackson.idfed.authorize',
      counterOptions: { description: 'Number of identity federation authorize requests' },
      counterAttributes,
    });
  },
  idfedAuthorizeError: (counterAttributes: CounterOperationParams['counterAttributes']) => {
    incrementCounter({
      meter: METER,
      name: 'jackson.idfed.authorize.error',
      counterOptions: { description: 'Number of errors in identity federation authorize requests' },
      counterAttributes,
    });
  },
  idfedResponse: (counterAttributes: CounterOperationParams['counterAttributes']) => {
    incrementCounter({
      meter: METER,
      name: 'jackson.idfed.response',
      counterOptions: { description: 'Number of identity federation response requests' },
      counterAttributes,
    });
  },
  idfedResponseError: (counterAttributes: CounterOperationParams['counterAttributes']) => {
    incrementCounter({
      meter: METER,
      name: 'jackson.idfed.response.error',
      counterOptions: { description: 'Number of errors in identity federation response requests' },
      counterAttributes,
    });
  },
};

const gauges = {
  dbMaxConnections: (val, gaugeAttributes: CounterOperationParams['counterAttributes']) =>
    observeGauge({
      meter: METER,
      name: 'jackson.db.connections.max',
      val,
      gaugeOptions: { description: 'Maximum number of db connections' },
      gaugeAttributes,
    }),
  dbTotalConnections: (val, gaugeAttributes: CounterOperationParams['counterAttributes']) =>
    observeGauge({
      meter: METER,
      name: 'jackson.db.connections.total',
      val,
      gaugeOptions: { description: 'Total number of db connections' },
      gaugeAttributes,
    }),
  dbIdleConnections: (val, gaugeAttributes: CounterOperationParams['counterAttributes']) =>
    observeGauge({
      meter: METER,
      name: 'jackson.db.connections.idle',
      val,
      gaugeOptions: { description: 'Number of idle db connections' },
      gaugeAttributes,
    }),
  dbWaitingConnections: (val, gaugeAttributes: CounterOperationParams['counterAttributes']) =>
    observeGauge({
      meter: METER,
      name: 'jackson.db.connections.waiting',
      val,
      gaugeOptions: { description: 'Number of waiting db connections' },
      gaugeAttributes,
    }),
};

const increment = (
  action: keyof typeof counters,
  counterAttributes?: CounterOperationParams['counterAttributes']
) => {
  const counterIncrement = counters[action];
  if (typeof counterIncrement === 'function') {
    counterIncrement(counterAttributes);
  }
};

const gauge = (
  action: keyof typeof gauges,
  val,
  gaugeAttributes?: CounterOperationParams['counterAttributes']
) => {
  const gaugeRegister = gauges[action];
  if (typeof gaugeRegister === 'function') {
    gaugeRegister(val, gaugeAttributes);
  }
};

export { increment, gauge };
