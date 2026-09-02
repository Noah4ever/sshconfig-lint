const assert = require('node:assert/strict');
const test = require('node:test');

const { ruleGuides } = require('../dist/rules.js');

const publicRuleCodes = [
  'INVALID_VALUE',
  'DUP_HOST',
  'MISSING_IDENTITY',
  'WILDCARD_ORDER',
  'WEAK_ALGO',
  'DUP_DIRECTIVE',
  'INSECURE_OPT',
  'UNSAFE_CTRL_PATH',
  'INCLUDE_CYCLE',
  'INCLUDE_DEPTH',
  'INCLUDE_READ',
  'INCLUDE_GLOB',
  'INCLUDE_NO_MATCH',
  'NEGATED_HOST',
  'PROXY_CONFLICT',
  'REVOKED_HOST_KEYS_UNREADABLE',
  'MISSING_CERTIFICATE',
  'LOCAL_COMMAND_DISABLED',
  'INVALID_TOKEN',
];

test('offers a guide for every public diagnostic', () => {
  assert.deepEqual(ruleGuides.map(([code]) => code), publicRuleCodes);
  for (const [code, slug] of ruleGuides) {
    assert.match(code, /^[A-Z][A-Z_]+$/);
    assert.match(slug, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
  }
});
