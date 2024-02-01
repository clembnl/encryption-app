let crypto;
try {
  crypto = require('node:crypto');
  console.log('ok')
} catch (err) {
  console.error('crypto support is disabled!');
} 