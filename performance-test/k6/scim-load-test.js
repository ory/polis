import http from 'k6/http';
import { check, sleep } from 'k6';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

// Custom metrics
export const errorCount = new Counter('errors');

// Load test options
export const options = {
  discardResponseBodies: false,
  thresholds: {
    // http_req_duration: ['p(95)<500'], // 95% of requests should complete in under 500ms
    errors: ['count<1'], // Fewer than 1 error allowed
  },
  scenarios: {
    load_test: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 45 },
        { duration: '40s', target: 55 },
        { duration: '20s', target: 0 },
      ],
    },
  },
};

const BASE_URL = 'http://localhost:5225';
const API_V1 = `${BASE_URL}/api/v1`;

const manageHeaders = {
  Authorization: 'Api-Key secret',
  'Content-Type': 'application/json',
};

const _cache = {};

function generateUserPayload() {
  const userName = `user-${randomString(8)}`;
  const email = `${userName}@example.com`;

  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: userName,
    name: {
      givenName: 'Test',
      familyName: 'User',
    },
    emails: [
      {
        primary: true,
        value: email,
        type: 'work',
      },
    ],
    active: true,
  };
}

function generateGroupPayload() {
  const groupName = `group-${randomString(8)}`;

  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName: groupName,
    members: [],
  };
}

export async function setup() {
  // For example: Create initial directory

  const directoryPayload = {
    tenant: 'performance-test-boxyhq',
    product: 'scim-saml-jackson',
    name: 'load-test-scim',
    type: 'okta-scim-v2',
    webhook_url: '',
    webhook_secret: '',
  };

  const response = await http.asyncRequest('POST', `${API_V1}/dsync`, JSON.stringify(directoryPayload), {
    headers: manageHeaders,
  });

  const isSuccessful = check(response, {
    'Directory creation Response status is 201': (r) => r.status === 201,
  });

  if (isSuccessful) {
    const { data } = response.json();

    console.log(`SCIM Directory created successfully for tenant: ${data.tenant}, product: ${data.product}`);
    return { directoryId: data.id, scim: data.scim };
  } else {
    errorCount.add(1);
    console.error(
      `SCIM directory creation failed Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
    exec.test.abort('create directory connection status code was *not* 200');
  }
}

export async function teardown({ directoryId }) {
  // Delete directory
  await http.asyncRequest('DELETE', `${API_V1}/dsync/${directoryId}`, null, {
    headers: { Authorization: manageHeaders['Authorization'] },
  });
}

export default async function loadTest({ scim }) {
  // Users
  await createUser({ scim });
  await getUser({ scim });
  await listUsers({ scim });
  await updateUser({ scim });
  await replaceUser({ scim });

  // Groups
  await createGroup({ scim });
  await getGroup({ scim });
  await listGroups({ scim });
  await updateGroup({ scim });
  await addUserToGroup({ scim });
  await removeUserFromGroup({ scim });
  await deleteGroup({ scim });

  // Finally delete the user
  await deleteUser({ scim });

  sleep(1);
}

// User Operations
async function createUser({ scim }) {
  const payload = generateUserPayload();

  const response = await http.asyncRequest('POST', `${scim.endpoint}/Users`, JSON.stringify(payload), {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'createUser Response status is 201': (r) => r.status === 201,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    _cache.userId = responseData.id;
    console.log(`User created successfully with ID: ${responseData.id}`);
  } else {
    errorCount.add(1);
    console.error(`User creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function getUser({ scim }) {
  const response = await http.asyncRequest('GET', `${scim.endpoint}/Users/${_cache.userId}`, null, {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'getUser Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`User retrieved successfully: ${responseData.userName}`);
  } else {
    errorCount.add(1);
    console.error(`Get user failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function listUsers({ scim }) {
  const response = await http.asyncRequest('GET', `${scim.endpoint}/Users`, null, {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'listUsers Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`Users listed successfully. Total users: ${responseData.totalResults}`);
  } else {
    errorCount.add(1);
    console.error(`List users failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function updateUser({ scim }) {
  const payload = {
    Operations: [
      {
        op: 'replace',
        value: {
          active: false,
          name: { givenName: 'Updated', familyName: 'User' },
        },
      },
    ],
  };

  const response = await http.asyncRequest(
    'PATCH',
    `${scim.endpoint}/Users/${_cache.userId}`,
    JSON.stringify(payload),
    {
      headers: {
        Authorization: `Bearer ${scim.secret}`,
      },
    }
  );

  const isSuccessful = check(response, {
    'updateUser Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`User updated successfully: ${responseData.userName}`);
  } else {
    errorCount.add(1);
    console.error(`Update user failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function replaceUser({ scim }) {
  const payload = {
    ...generateUserPayload(),
    name: { givenName: 'Replaced', familyName: 'User' },
    active: true,
  };

  const response = await http.asyncRequest(
    'PUT',
    `${scim.endpoint}/Users/${_cache.userId}`,
    JSON.stringify(payload),
    {
      headers: {
        Authorization: `Bearer ${scim.secret}`,
      },
    }
  );

  const isSuccessful = check(response, {
    'replaceUser Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`User replaced successfully: ${responseData.userName}`);
  } else {
    errorCount.add(1);
    console.error(`Replace user failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function deleteUser({ scim }) {
  const response = await http.asyncRequest('DELETE', `${scim.endpoint}/Users/${_cache.userId}`, null, {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'deleteUser Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`User deleted successfully: ${_cache.userId}`);
  } else {
    errorCount.add(1);
    console.error(`Delete user failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

// Group Operations
async function createGroup({ scim }) {
  const payload = generateGroupPayload();

  const response = await http.asyncRequest('POST', `${scim.endpoint}/Groups`, JSON.stringify(payload), {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'createGroup Response status is 201': (r) => r.status === 201,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    _cache.groupId = responseData.id;
    console.log(`Group created successfully with ID: ${responseData.id}`);
  } else {
    errorCount.add(1);
    console.error(`Group creation failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function getGroup({ scim }) {
  const response = await http.asyncRequest('GET', `${scim.endpoint}/Groups/${_cache.groupId}`, null, {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'getGroup Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`Group retrieved successfully: ${responseData.displayName}`);
  } else {
    errorCount.add(1);
    console.error(`Get group failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function listGroups({ scim }) {
  const response = await http.asyncRequest('GET', `${scim.endpoint}/Groups`, null, {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'listGroups Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`Groups listed successfully. Total groups: ${responseData.totalResults}`);
  } else {
    errorCount.add(1);
    console.error(`List groups failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function updateGroup({ scim }) {
  const payload = {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [
      {
        op: 'replace',
        value: {
          displayName: 'Updated Group Name',
        },
      },
    ],
  };

  const response = await http.asyncRequest(
    'PATCH',
    `${scim.endpoint}/Groups/${_cache.groupId}`,
    JSON.stringify(payload),
    {
      headers: {
        Authorization: `Bearer ${scim.secret}`,
      },
    }
  );

  const isSuccessful = check(response, {
    'updateGroup Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    const responseData = JSON.parse(response.body);
    console.log(`Group updated successfully: ${responseData.displayName}`);
  } else {
    errorCount.add(1);
    console.error(`Update group failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}

async function addUserToGroup({ scim }) {
  const payload = {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [
      {
        op: 'add',
        path: 'members',
        value: [
          {
            value: _cache.userId,
            display: _cache.userName,
          },
        ],
      },
    ],
  };

  const response = await http.asyncRequest(
    'PATCH',
    `${scim.endpoint}/Groups/${_cache.groupId}`,
    JSON.stringify(payload),
    {
      headers: {
        Authorization: `Bearer ${scim.secret}`,
      },
    }
  );

  const isSuccessful = check(response, {
    'addUserToGroup Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`User ${_cache.userId} added to group ${_cache.groupId} successfully`);
  } else {
    errorCount.add(1);
    console.error(
      `Add user to group failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function removeUserFromGroup({ scim }) {
  const payload = {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [
      {
        op: 'remove',
        path: `members[value eq "${_cache.userId}"]`,
      },
    ],
  };

  const response = await http.asyncRequest(
    'PATCH',
    `${scim.endpoint}/Groups/${_cache.groupId}`,
    JSON.stringify(payload),
    {
      headers: {
        Authorization: `Bearer ${scim.secret}`,
      },
    }
  );

  const isSuccessful = check(response, {
    'removeUserFromGroup Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`User ${_cache.userId} removed from group ${_cache.groupId} successfully`);
  } else {
    errorCount.add(1);
    console.error(
      `Remove user from group failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`
    );
  }
}

async function deleteGroup({ scim }) {
  const response = await http.asyncRequest('DELETE', `${scim.endpoint}/Groups/${_cache.groupId}`, null, {
    headers: {
      Authorization: `Bearer ${scim.secret}`,
    },
  });

  const isSuccessful = check(response, {
    'deleteGroup Response status is 200': (r) => r.status === 200,
  });

  if (isSuccessful) {
    console.log(`Group deleted successfully: ${_cache.groupId}`);
  } else {
    errorCount.add(1);
    console.error(`Delete group failed. Status: ${response.status}, Response: ${JSON.stringify(response)}`);
  }
}
