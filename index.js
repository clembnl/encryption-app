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

import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

let option = '0';

console.log('Option 1 : encrypt and decrypt a message.')
console.log('Option 2 : sign and verify a file')
while (not ['1','2'].includes(option)) {
  rl.question('Please choose an option? ', (value) => {
    option = value;
    if (['1','2'].includes(option)) {
      console.log(`You choose option ${option}`);
    }
    else console.error('This is not a valid input.');
    rl.close();
  });
};

switch (option) {
  case '1':
    let secret = '';
    let message = '';
    let hashalgo = '';
    let encryptionalgo = '';
    let asymalgo = '';

    rl.question('Please enter a secret key to encrypt your message', (value) => {
      secret = value;
      rl.close();
    });

    console.log('In order to use a symetric algorithm to encrypt your message we will need to have a specific length (here 128bits) in order to do so we will hash your secret key');
    console.log('Here are the hash algorithms available: ');
    console.log('sha256');
    console.log('blake2');
    console.log('blake3');
    console.log('kangarootwelve');
    while (not ['sha256', 'blake2', 'blake3', 'kangarootwelve'].includes(hashalgo)) {
      rl.question('Please choose a hash algorithm', (value) => {
        hashalgo = value;
        if (['sha256', 'blake2', 'blake3', 'kangarootwelve'].includes(hashalgo)) {
          console.log(`You chose ${hashalgo}`);
        }
        else console.error('This is not a valid input.');
        rl.close();
      });
    };
    const hashValue = Encrypt.hash(secret, hashalgo);
    console.log('Here is the hash of your secret key :');
    console.log(hashValue);

    console.log('As state before, we will use a symetric encryption algorithm to encrypt your message. These are fast and secure. In particular AES-128 has yet to be broken.');
    console.log('Here are the symetric encryption algorithms available: ');
    console.log('AES-128-CBC');
    console.log('BlowFish-CBC');
    while (not ['AES-128-CBC', 'BlowFish-CBC'].includes(encryptionalgo)) {
      rl.question('Please choose a symetric encryption algorithm', (value) => {
        encryptionalgo = value;
        if (['AES-128-CBC', 'BlowFish-CBC'].includes(encryptionalgo)) {
          console.log(`You chose ${encryptionalgo}`);
        }
        else console.error('This is not a valid input.');
        rl.close();
      });
    };
    rl.question('Please enter the message you want to encrypt', (value) => {
      message = value;
      rl.close();
    });
    const encryptedMessage = Encrypt.symEncrypt(hashValue, encryptionalgo, message);
    console.log('Here is your encrypted message :')
    console.log(encryptedMessage);

    console.log('In order for the recipient to be able to decrypt your message we will need to encrypt your secret key. For this purpose asymetric encryption algorithm are the most secured.');
    console.log('Here are the asymetric encryption algorithms available: ');
    console.log('RSA-3072');
    console.log('ECDSA-256');
    while (not ['RSA-3072', 'ECDSA-256'].includes(asymalgo)) {
      rl.question('Please choose an asymetric encryption algorithm', (value) => {
        asymalgo = value;
        if (['AES-128-CBC', 'BlowFish-CBC'].includes(asymalgo)) {
          console.log(`You chose ${asymalgo}`);
        }
        else console.error('This is not a valid input.');
        rl.close();
      });
    };
    const { publicKey, privateKey } = Encrypt.asymKeys(asymalgo);
    console.log('Here is the public key used to encrypt anything you want to share :');
    console.log(publicKey);
    console.log('Here is the private key that you have to keep private in order to decrypt anything that has been encrypted with the public key.');
    console.log('That way when you want to someone to share something confidential with you, you can give them your public key that they can use to encrypt.');
    console.log('and only you, owner of the private key will be able to decrypt it.');
    console.log(privateKey);

    const encryptedKey = Encrypt.asymEncrypt(hashalgo, publicKey);
    console.log('Here is your secret key that has been encrypted with the public key.');
    console.log(encryptedKey);

    let encryptedKeyTest = '';
    let privateKeytest = '';
    let messageTest = '';
    let decryptedKeyTest = '';
    rl.question('Now as the receiver we can decrypt the encrypted key in order to decrypt the encrypted message: ', (value) => {
      encryptedKeyTest = value;
      rl.close();
    });
    rl.question('Please enter your private key: ', (value) => {
      privateKeytest = value;
      rl.close();
    });
    const decryptedKey = Encrypt.asymDecrypt(encryptedKeyTest, privateKeytest);
    console.log('Here is the decrypted secret key :')
    console.log(decryptedKey);
    console.log('You can verify that it is the same as the hash provided before.')

    rl.question('Now we can decrypt the message using this key. Please enter the encrypted message: ', (value) => {
      messageTest = value;
      rl.close();
    });
    rl.question('And the decrypted key: ', (value) => {
      decryptedKeyTest = value;
      rl.close();
    });
    const decryptedMessage = Encrypt.symDecrypt(decryptedKeyTest, messageTest);
    console.log('Good job here is the decrypted message :')
    console.log(decryptedMessage)
    console.log('Please verify that it is indeed your original message')
    
  case '2':
    //call sign function 
  default:
    break;
}