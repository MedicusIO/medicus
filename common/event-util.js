const get = require('lodash/get');
const intersection = require('lodash/intersection');
const merge = require('lodash/merge');
const bourne = require('@hapi/bourne');
const Validator = require('fastest-validator');

/* Returns an input object with the following:
{
  userId: '269efc6f-f663-494e-a2e6-26cdee5759f4',
  groups: [
    'NoAuth',
    'groupA',
    'groupB',
    'Medicus_global',
    'Medicus_user'
  ],
  params: {
    cognitoID: 'newPerson3',
    surname: 'Tilley',
    ID: 'sddfdf',
    id: 'helloKitty'
  },
}
*/

const processEvent = (event) => {
  const {
    pathParameters, queryStringParameters, requestContext,
  } = event;
  const cognitoID = get(requestContext, 'authorizer.jwt.claims.username') || undefined;
  const groupString = (get(requestContext, 'authorizer.jwt.claims.cognito:groups') || '')
    .replace('[', '')
    .replace(']', '');
  const cognitoGroups = groupString.split(' ');
  // Add NoAuth for functions that require no authorisation
  const groups = ['NoAuth', ...cognitoGroups];
  const body = bourne.parse(event.body || '{}');
  return {
    userID: groups.find((value) => value.startsWith('medicus_')),
    groups,
    cognitoID,
    params: merge(body, pathParameters, queryStringParameters),
  };
};

const processResponse = (httpCode, dataObject) => ({
  statusCode: httpCode,
  body: JSON.stringify(dataObject),
});

const validate = (schema, suppliedParams) => {
  const v = new Validator();
  const check = v.compile(schema);
  return check(suppliedParams);
};

const runner = async (event, schema, authorisedGroups, main, returnRequest) => {
  let currentHTTPErrorCode;
  let parsed;
  const returnReq = returnRequest || false;
  try {
    // parse the user input
    currentHTTPErrorCode = 400;
    parsed = processEvent(event);

    // check that we managed to get isolate the internal ID
    if (!parsed.userID.startsWith('medicus_')) {
      throw new Error('Internal ID missing');
    }

    // check that there are authorisedGroups supplied
    currentHTTPErrorCode = 501;
    const authGroups = authorisedGroups || [];
    if (authGroups.length === 0) {
      throw new Error('Cannot run functions without authorisation groups');
    }

    // now validate auth
    currentHTTPErrorCode = 401;
    if (intersection(parsed.groups, authGroups).length === 0) {
      throw new Error('Unauthorised');
    }

    // now run validation of input data
    currentHTTPErrorCode = 400;
    const validationResult = validate(schema, parsed.params);
    if (validationResult !== true) {
      if (returnReq === true) {
        throw new Error(JSON.stringify(validationResult));
      } else {
        throw new Error('Failed validation');
      }
    }

    // now run the actual function
    currentHTTPErrorCode = 500;
    const result = await main(parsed) || {
      msg: 'No data returned from function',
    };
    currentHTTPErrorCode = 200;
    if (returnReq === true) {
      result.event = parsed;
    }
    return processResponse(currentHTTPErrorCode, result);
  } catch (e) {
    const error = {
      err: e.message,
    };
    if (returnReq === true) {
      error.event = parsed;
    }
    return processResponse(currentHTTPErrorCode, error);
  }
};

module.exports = {
  processEvent,
  processResponse,
  runner,
};
