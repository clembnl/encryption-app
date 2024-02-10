// HASH FUNCTION //

import { sha256 } from '@noble/hashes/sha256';
import { blake2s } from '@noble/hashes/blake2s';
import { blake3 } from '@noble/hashes/blake3';
import { k12 } from '@noble/hashes/sha3-addons';
import * as crypto from 'crypto';

const iv_aes = crypto.randomBytes(16);
const iv_bf = crypto.randomBytes(8);

function hash(secretKey, algorithm) {
    switch (algorithm) {
        case 'sha256':
            return Buffer.from(sha256(secretKey)).toString('hex');
        case 'blake2':
            return Buffer.from(blake2s(secretKey)).toString('hex');
        case 'blake3':
            return Buffer.from(blake3(secretKey)).toString('hex');
        case 'kangarootwelve':
            return Buffer.from(k12(secretKey)).toString('hex');
        default:
            throw Error('Invalid input');
    }
};

//console.log(hash('test', 'sha256'));

function symEncrypt(hashValue, encryptionalgo, message) {
    hashValue = Buffer.from(hashValue, 'hex');

    switch (encryptionalgo) {
        case 'AES-256-CBC' :
            const cipher_aes = crypto.createCipheriv('aes-256-cbc', hashValue, iv_aes);
            return Buffer.concat([cipher_aes.update(message), cipher_aes.final()]).toString('hex');

        case 'BlowFish-CBC':
            const cipher_bf = crypto.createCipheriv('bf-cbc', hashValue, iv_bf);
            return Buffer.concat([cipher_bf.update(message), cipher_bf.final()]).toString('hex');
            
        default :
            throw Error('Invalid input');
    }
};

function asymKeys() {
    return crypto.generateKeyPairSync('rsa', { 
        modulusLength: 3072,    // Options 
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

function asymEncrypt(publicKey, hashValue) {
    return Buffer.from(crypto.publicEncrypt(publicKey, Buffer.from(hashValue, 'hex'))).toString('hex');
};

function asymDecrypt(privateKey, encryptedKey) {
    return Buffer.from(crypto.privateDecrypt(privateKey, Buffer.from(encryptedKey, 'hex'))).toString('hex');
};

function symDecrypt(decryptedKey, encryptedMessage, encryptionalgo) {
    const hashValue = Buffer.from(decryptedKey, 'hex');
    const messageFormated = Buffer.from(encryptedMessage, 'hex');

    switch (encryptionalgo) {
        case 'AES-256-CBC' :
            const decipher_aes = crypto.createDecipheriv('aes-256-cbc', hashValue, iv_aes);
            return Buffer.concat([decipher_aes.update(messageFormated), decipher_aes.final()]).toString();

        case 'BlowFish-CBC':
            const decipher_bf = crypto.createDecipheriv('bf-cbc', hashValue, iv_bf);
            return Buffer.concat([decipher_bf.update(messageFormated), decipher_bf.final()]).toString();
            
        default :
            throw Error('Invalid input');
    }
};

// TEST

const encryptedMessageTest = symEncrypt('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'BlowFish-CBC', 'test');
console.log(encryptedMessageTest);
console.log('////////////////////');
/*
const keys = asymKeys();
const encryptedKeyTest = asymEncrypt(keys.publicKey, '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
console.log(encryptedKeyTest)
console.log('////////////////////');
const decryptedKeytest = asymDecrypt(keys.privateKey, encryptedKeyTest);
console.log(decryptedKeytest);
console.log('////////////////////');
const decryptedMessageTest = symDecrypt(decryptedKeytest, encryptedMessageTest, 'BlowFish-CBC');
console.log(decryptedMessageTest);
*/

const decryptedMessageTest = symDecrypt('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', encryptedMessageTest, 'BlowFish-CBC');
console.log(decryptedMessageTest);

