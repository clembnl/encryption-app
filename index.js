// HASH //
/*
import { sha256 } from '@noble/hashes/sha256';
import { blake2s } from '@noble/hashes/blake2s';
import { blake3 } from '@noble/hashes/blake3';
import { k12 } from '@noble/hashes/sha3-addons';

console.log(Buffer.from(sha256('test')).toString('hex'));
console.log(Buffer.from(blake2s('test')).toString('hex'));
console.log(Buffer.from(blake3('test')).toString('hex'));
console.log(Buffer.from(k12('test')).toString('hex'));
*/
// ENCRYPT SYM //
import crypto from 'crypto';
const key16 = 'LQ3zOFI6XzDZipYl'
/*
// AES
crypto.randomFill(new Uint8Array(16), (err, iv) => {
  if (err) throw err;

  const cipher = crypto.createCipheriv('aes-128-cbc', key16, iv);
  cipher.setEncoding('hex');

  let encrypted_aes = '';

  cipher.on('data', (chunk) => encrypted_aes += chunk);
  cipher.on('end', () => console.log(encrypted_aes));

  cipher.write('test');
  cipher.end();
});*/

/*
// Blowfish
crypto.randomFill(new Uint8Array(8), (err, iv) => {
  if (err) throw err;

  const cipher = crypto.createCipheriv('bf-cbc', key16, iv);
  cipher.setEncoding('hex');

  let encrypted_bf = '';

  cipher.on('data', (chunk) => encrypted_bf += chunk);
  cipher.on('end', () => console.log(encrypted_bf));

  cipher.write('test');
  cipher.end();
});
*/

// ENCRYPT ASYM //
/*
// ECDSA-256
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { 
  namedCurve: 'secp256k1',    // Options 
  publicKeyEncoding: { 
    type: 'spki', 
    format: 'der'
  }, 
  privateKeyEncoding: { 
    type: 'pkcs8', 
    format: 'der'
  } 
}); 
  
// Prints asymmetric key pair 
console.log("The public key is: ", Buffer.from(publicKey).toString('hex')); 
console.log(); 
console.log("The private key is: ", Buffer.from(privateKey).toString('hex'));
*/

/*
// RSA 3072
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { 
  modulusLength: 3072,    // Options 
  publicKeyEncoding: { 
    type: 'spki', 
    format: 'der'
  }, 
  privateKeyEncoding: { 
    type: 'pkcs8', 
    format: 'der'
  } 
}); 
  
// Prints asymmetric key pair 
console.log("The public key is: ", Buffer.from(publicKey).toString('hex')); 
console.log(); 
console.log("The private key is: ", Buffer.from(privateKey).toString('hex'));
*/

