const readline = require('readline');
const Encrypt = require('./encrypt.js');
const Sign = require('./sign.js');

const colors = {
  black: "\x1b[30m%s\x1b[0m",
  red: "\x1b[31m%s\x1b[0m",
  green: "\x1b[32m%s\x1b[0m",
  yellow: "\x1b[33m%s\x1b[0m",
  blue: "\x1b[34m%s\x1b[0m",
  magenta: "\x1b[35m%s\x1b[0m",
  cyan: "\x1b[36m%s\x1b[0m",
  white: "\x1b[37m%s\x1b[0m",
  gray: "\x1b[90m%s\x1b[0m",
  crimson: "\x1b[38m%s\x1b[0m" // Scarlet
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const delay = ms => new Promise(resolve => setTimeout(resolve, ms))

function question(questionAsked) {
  rl.stdoutMuted = false;
  return new Promise(res => rl.question(questionAsked, value => res(value)));
};

function questionWithHiddenAnswer(questionAsked) {
  console.log(questionAsked);
  rl.stdoutMuted = true;
  return new Promise(res => rl.question('', value => res(value)));
}

rl._writeToOutput = function _writeToOutput(stringToWrite) {
  if (rl.stdoutMuted) {
    rl.output.write("*");
    return stringToWrite;
  }
  else {
    rl.output.write(stringToWrite);
    return stringToWrite;
  }
};

async function main() {
  console.log('Option 1 : encrypt and decrypt a message.');
  console.log('Option 2 : sign and verify a message');
  let option = await question('Please choose an option? ');
  console.log(`You choose option ${option}`);
  console.log('//////////');
  console.log('\t');

  switch (option) {
    case '1':
      let secret = await questionWithHiddenAnswer('Please enter a secret key to encrypt your message: ');
      console.log('\t');

      console.log('In order to use a symetric algorithm to encrypt your message we will need to have a specific length (here 128bits)');
      console.log('in order to do so we will hash your secret key');
      console.log('\t');
      console.log('Here are the hash algorithms available: ');
      console.log('sha256');
      console.log('blake2');
      console.log('blake3');
      console.log('kangarootwelve');
      let hashalgo = await question('Please choose a hash algorithm: ');
      let hashValue = '';
      try {
        hashValue = Encrypt.hash(secret, hashalgo);
      } catch (e) {
        console.error(colors.red, e.message);
        rl.close()
        return 1;
      }
      console.log('\t');
      console.log('Here is the hash of your secret key: ');
      console.log(colors.yellow, hashValue);
      console.log('\t');

      console.log('As state before, we will use a symetric encryption algorithm to encrypt your message. These are fast and secure. In particular AES-256 has yet to be broken and is used by the US Government for \'Top Secret\' files !');
      console.log('Here are the symetric encryption algorithms available: ');
      console.log('AES-256-CBC');
      console.log('BlowFish-CBC');
      let encryptionalgo = await question('Please choose a symetric encryption algorithm: ');
      console.log('\t');

      let message1 = await question('Please enter the message you want to encrypt: ');
      let encryptedMessage = '';
      try {
        encryptedMessage = Encrypt.symEncrypt(hashValue, encryptionalgo, message1);
      } catch (e) {
        console.error(colors.red, e.message);
        rl.close()
        return 1;
      }
      console.log('Here is your encrypted message: ')
      console.log(colors.green, encryptedMessage);
      console.log('\t');
    
      console.log('In order for the recipient to be able to decrypt your message we will need to encrypt your secret key.');
      console.log('For this purpose asymetric encryption algorithm are the most secured.');
      console.log('Here we are using RSA-3072');

      await delay(2000);

      const keys1 = Encrypt.asymKeys();
      console.log('Here is the public key that you can give to anyone so they can use it to encrypt anything they want to share with you: ');
      console.log(colors.blue, keys1.publicKey);
      await delay(2000);
      console.log('Here is the private key that you have to keep private in order to decrypt anything that has been encrypted with the public key.');
      console.log('So only you, owner of the private key, will be able to decrypt it:');
      console.log(colors.red, keys1.privateKey);
      await delay(2000);

      const encryptedKey = Encrypt.asymEncrypt(keys1.publicKey, hashValue);
      console.log('Here is your secret key that has been encrypted with the public key.');
      console.log(colors.magenta, encryptedKey);
      console.log('\t');

      await delay(1000);

      let encryptedKeyTest = await question('Now as the receiver we want to decrypt the key in order to decrypt the encrypted message, please enter the encrypted key (value in magenta): ');
      console.log('\t');
      console.log('Using the private key given before we are able to decrypt the secret key: ')
      const decryptedKey = Encrypt.asymDecrypt(keys1.privateKey, encryptedKeyTest);
      console.log(colors.yellow, decryptedKey);
      console.log('\t');
      console.log('You can verify that it is the same as the hash provided before (value in yellow).');
      console.log('\t');

      await delay(3000);

      let encrpytedMessageTest = await question('Now we can decrypt the message using this key. Please enter the encrypted message (value in green): ');
      let decryptedKeyTest = await question('And the decrypted key (value in yellow): ');

      const decryptedMessage = Encrypt.symDecrypt(decryptedKeyTest, encrpytedMessageTest, encryptionalgo);
      console.log('\t');
      console.log('Good job here is the decrypted message: ')
      console.log(colors.cyan, decryptedMessage)
      console.log('Please verify that it is indeed your original message.')
      console.log('\t');

      rl.close();
      return 1;
    
    case '2':
      console.log('By signing your message or a file, the receiver can authentify the sender and ensure that its content has not been altered.');
      console.log('The signature is an ecrypted hash of the message or file.');
      console.log('\t');
      console.log('The verification of the message is done by comparing the decrypted signature from the original message with the hash of the received message.');
      console.log('\t');
      console.log('The encryption methods used for numeric signature are asymetric algortihm with a private key used by the sender to encrypt the signature.');
      console.log('and a public key generated by the sender that he can share publicly and that will be used to decrypt the signature and thus veritfy the message.');
      console.log('\t');

      let message2 = await question('Please enter a message you want to sign : ');
      console.log('\t');
      console.log('So first the message will be hashed. Here we will use the most common and used hash algorithm : SHA-256 ');
      const hashedMessage2 = Sign.hash(message2);
      console.log('Here is the hash of your message : ');
      console.log(colors.yellow, hashedMessage2);
      console.log('\t');

      await delay(1000);

      console.log('Now we will encrypt it with an ECDSA-256 asymetric encryption algorithm');
      const keys2 = Sign.generateKeys();
      console.log('Here is the private key that the sender should keep private and that will be used to sign messages or files :');
      console.log(colors.red, keys2.privateKey);
      console.log('And this is the public key that the sender can share with the message so that people can verify that the message they receive come from the original sender and has been untouched :');
      console.log(colors.blue, keys2.publicKey);
      console.log('\t');
      console.log('Thus it is also the key that we will used to decrypt the signature and compare it with the hash of the received message.');

      await delay(5000);

      const signature = Sign.sign(message2, keys2.privateKey);
      console.log('Here is the signature : ');
      console.log(colors.green, signature);
      console.log('\t');

      await delay(1000);

      let message2bis = await question('Please enter the same message that you used at first.')

      console.log('If it is the same message the verification function will return "true" : ');
      const verifyTest1 = Sign.verify(message2bis, keys2.publicKey, signature);
      console.log(colors.cyan, verifyTest1);
      console.log('If "true" is returned: good the message is verified !');
      console.log('If "false" is returned: it means that you gave a different message than the original one.')

      await delay(2000);

      console.log('\t');
      console.log('You can try again here to see the opposite result : ');
      console.log('(put a different message is "true" was return before)');
      console.log('(put the original message is "false" was return before)');

      console.log('\t');
      let message2Fake = await question('Please enter the message you want to verify : ');
      const verifyTest2 = Sign.verify(message2Fake, keys2.publicKey, signature);
      console.log(colors.cyan, verifyTest2);
      console.log('\t');
      console.log('This is very useful for messaging app or to share files and verify that they have not been modified with virus or malware.')
      console.log('\t');

      rl.close();
      return 1;

    default:
      rl.close();
      return 1;
  }
};

main();