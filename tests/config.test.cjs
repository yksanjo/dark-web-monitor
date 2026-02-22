const test = require('node:test');
const assert = require('node:assert/strict');
const { validateDomains, isValidDomain } = require('../src/config');

test('validateDomains normalizes and filters values', () => {
  const out = validateDomains(['https://Example.com/path', 'bad_domain', 'api.test.io/']);
  assert.deepEqual(out, ['example.com', 'api.test.io']);
  assert.equal(isValidDomain('example.com'), true);
  assert.equal(isValidDomain('bad_domain'), false);
});
