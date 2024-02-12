import * as crypto from 'crypto';

function hash(message) {
    return crypto.createHash('sha256').update(message).digest('hex');
};
module.exports.hash = hash;

function generateKeys() {
    return crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: { 
            type: 'spki', 
            format: 'pem'
        }, 
        privateKeyEncoding: { 
            type: 'pkcs8', 
            format: 'pem'
        } 
    });
};
module.exports.generateKeys = generateKeys;

function sign(data, privateKey) {
    return crypto.sign('sha256', data, privateKey).toString('hex');
};
module.exports.sign = sign;

function verify(data, publicKey, signature) {
    return crypto.verify('sha256', data, publicKey, Buffer.from(signature, 'hex'));
};
module.exports.verify = verify;

/// TESTS
/*
const hashMessage = hash('message');
console.log(hashMessage);
const keys = generateKeys();
const signatureTest = encrypt('message', keys.privateKey);
console.log(signatureTest)
const decryptedSignature = decrypt('message2', keys.publicKey, signatureTest);
console.log(decryptedSignature);
*/