# Steps to run k6

1. installation: sudo apt-get install k6 or refer this https://grafana.com/docs/k6/latest/set-up/install-k6/
2. for run: cd performance-test/k6
3. run command: k6 run <test-file>.js

# Test results (ran on Macbook M1 Pro)

## Test Environment

- Hardware: Apple MacBook Pro (M1, 2021)
- Processor: Apple M1 Pro
- Memory: 16GB

## SSO APIs Load Test Results

     ✓ createSSOConnection
     ✓ getSSOConnection
     ✓ updateSSOConnection
     ✓ getSSOConnectionByProduct
     ✓ deleteSSOConnection
     ✓ createSetupLink
     ✓ getSetUpLink
     ✓ deleteSetUpLink
     ✓ processing SAML IdP Response



     checks.........................: 100.00% 17065 out of 17065
     data_received..................: 19 MB   235 kB/s
     data_sent......................: 25 MB   310 kB/s

### Performance Metrics

| Metric                   | Avg     | Min   | Med     | Max     | p(90)    | p(95)   |
| ------------------------ | ------- | ----- | ------- | ------- | -------- | ------- |
| http_req_blocked         | 5.18µs  | 0s    | 3µs     | 1.89ms  | 5µs      | 7µs     |
| http_req_connecting      | 941ns   | 0s    | 0s      | 1.84ms  | 0s       | 0s      |
| http_req_duration        | 66.1ms  | 974µs | 13.31ms | 2.41s   | 221.15ms | 241.2ms |
| http_req_receiving       | 51.52µs | 6µs   | 31µs    | 14.87ms | 85µs     | 128µs   |
| http_req_sending         | 21.49µs | 2µs   | 11µs    | 10.03ms | 30µs     | 48µs    |
| http_req_tls_handshaking | 0s      | 0s    | 0s      | 0s      | 0s       | 0s      |
| http_req_waiting         | 66.03ms | 940µs | 13.24ms | 2.41s   | 221.04ms | 241.1ms |

### Additional Metrics

| Metric              | Value                                      |
| ------------------- | ------------------------------------------ |
| http_reqs           | 17066 (212.34/s)                           |
| http_req_failed     | 0.00% (0 out of 17066)                     |
| iteration_duration  | avg=1.59s, min=1.42s, med=1.53s, max=4.07s |
| iterations          | 1896 (23.59/s)                             |
| virtual users (VUs) | min=1, max=55                              |
| vus_max             | 55                                         |

running (1m20.4s), 00/55 VUs, 1896 complete and 0 interrupted iterations
load_test ✓ [======================================] 00/55 VUs 1m20s

## Directory Sync APIs Load Test Results

     ✓ createDSyncSetupLink
     ✓ getDSyncSetupLink
     ✓ getDSyncLinkByProduct
     ✓ deleteDSyncSetupLink
     ✓ CreateDirectory
     ✓ getDirectoryByTenantAndProduct
     ✓ getDirectoryById
     ✓ getDirectoryByProduct
     ✓ updateDirectoryName
     ✓ deleteDirectory

     checks.........................: 100.00% 23520 out of 23520
     data_received..................: 17 MB   205 kB/s
     data_sent......................: 5.7 MB  70 kB/s

### Performance Metrics

| Metric                   | Avg     | Min   | Med     | Max      | p(90)   | p(95)   |
| ------------------------ | ------- | ----- | ------- | -------- | ------- | ------- |
| http_req_blocked         | 4.72µs  | 0s    | 2µs     | 2.39ms   | 5µs     | 7µs     |
| http_req_connecting      | 987ns   | 0s    | 0s      | 1.11ms   | 0s      | 0s      |
| http_req_duration        | 27.79ms | 922µs | 21.82ms | 187.89ms | 58.51ms | 71.24ms |
| http_req_receiving       | 46.12µs | 6µs   | 25µs    | 15.42ms  | 74µs    | 119µs   |
| http_req_sending         | 18.66µs | 2µs   | 8µs     | 13.03ms  | 18µs    | 30µs    |
| http_req_tls_handshaking | 0s      | 0s    | 0s      | 0s       | 0s      | 0s      |
| http_req_waiting         | 27.73ms | 889µs | 21.77ms | 187.87ms | 58.44ms | 71.1ms  |

### Additional Metrics

| Metric              | Value                                     |
| ------------------- | ----------------------------------------- |
| http_reqs           | 23520 (290.54/s)                          |
| http_req_failed     | 0.00% (0 out of 23520)                    |
| iteration_duration  | avg=1.28s, min=1.02s, med=1.24s, max=1.6s |
| iterations          | 2352 (29.05/s)                            |
| virtual users (VUs) | min=1, max=55                             |
| vus_max             | 55                                        |

running (1m20.4s), 00/55 VUs, 1896 complete and 0 interrupted iterations
load_test ✓ [======================================] 00/55 VUs 1m20s

## SCIM APIs Load Test Results

     ✓ createUser
     ✓ getUser
     ✓ listUsers
     ✓ updateUser
     ✓ replaceUser
     ✓ createGroup
     ✓ getGroup
     ✓ listGroups
     ✓ updateGroup
     ✓ addUserToGroup
     ✓ removeUserFromGroup
     ✓ deleteGroup
     ✓ deleteUser


     checks.........................: 100.00% 23713 out of 23713
     data_received..................: 38 MB   469 kB/s
     data_sent......................: 7.3 MB  90 kB/s

### Performance Metrics

| Metric                   | Avg     | Min    | Med     | Max      | p(90)   | p(95)   |
| ------------------------ | ------- | ------ | ------- | -------- | ------- | ------- |
| http_req_blocked         | 5.5µs   | 0s     | 2µs     | 3.93ms   | 6µs     | 8µs     |
| http_req_connecting      | 1.15µs  | 0s     | 0s      | 3.82ms   | 0s      | 0s      |
| http_req_duration        | 50.08ms | 1.27ms | 48.05ms | 233.12ms | 88.82ms | 96.87ms |
| http_req_receiving       | 54.67µs | 6µs    | 29µs    | 8.83ms   | 98µs    | 151µs   |
| http_req_sending         | 15.55µs | 2µs    | 9µs     | 17.26ms  | 20µs    | 30µs    |
| http_req_tls_handshaking | 0s      | 0s     | 0s      | 0s       | 0s      | 0s      |
| http_req_waiting         | 50.01ms | 1.24ms | 47.96ms | 232.77ms | 88.78ms | 96.79ms |

### Additional Metrics

| Metric              | Value                                      |
| ------------------- | ------------------------------------------ |
| http_reqs           | 23714 (291.43/s)                           |
| http_req_failed     | 0.00% (0 out of 23714)                     |
| iteration_duration  | avg=1.65s, min=1.05s, med=1.79s, max=1.99s |
| iterations          | 1824 (22.42/s)                             |
| virtual users (VUs) | min=1, max=55                              |
| vus_max             | 55                                         |

running (1m21.4s), 00/55 VUs, 1824 complete and 0 interrupted iterations
load_test ✓ [======================================] 00/55 VUs 1m20s

## ID Federation Load Test Results

     ✓ createSAMLFederationApp
     ✓ getSAMLFederationApp
     ✓ updateSAMLFederationApp
     ✓ getSAMLFederationAppByProduct
     ✓ deleteSAMLFederationApp

     checks.........................: 100.00% 13670 out of 13670
     data_received..................: 11 MB   141 kB/s
     data_sent......................: 5.4 MB  67 kB/s

### Performance Metrics

| Metric                   | Avg     | Min   | Med    | Max      | p(90)   | p(95)   |
| ------------------------ | ------- | ----- | ------ | -------- | ------- | ------- |
| http_req_blocked         | 7.16µs  | 0s    | 3µs    | 4.76ms   | 7µs     | 11µs    |
| http_req_connecting      | 1.82µs  | 0s    | 0s     | 4.64ms   | 0s      | 0s      |
| http_req_duration        | 13.85ms | 150µs | 9.13ms | 127.18ms | 31.53ms | 47.21ms |
| http_req_receiving       | 62.62µs | 7µs   | 33µs   | 15.7ms   | 100µs   | 163µs   |
| http_req_sending         | 19.53µs | 2µs   | 9µs    | 15.2ms   | 24µs    | 40µs    |
| http_req_tls_handshaking | 0s      | 0s    | 0s     | 0s       | 0s      | 0s      |
| http_req_waiting         | 13.77ms | 121µs | 9.07ms | 127.15ms | 31.46ms | 47.1ms  |

### Additional Metrics

| Metric              | Value                                    |
| ------------------- | ---------------------------------------- |
| http_reqs           | 19138 (237.01/s)                         |
| http_req_failed     | 0.00% (0 out of 19138)                   |
| iteration_duration  | avg=1.1s, min=1.01s, med=1.1s, max=1.22s |
| iterations          | 2734 (33.86/s)                           |
| virtual users (VUs) | min=1, max=55                            |
| vus_max             | 55                                       |

running (1m20.7s), 00/55 VUs, 2734 complete and 0 interrupted iterations
load_test ✓ [======================================] 00/55 VUs 1m20s
