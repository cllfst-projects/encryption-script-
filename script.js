const crypto = require('crypto');
const rsa = require('node-rsa');
const assert = require('assert');

//generate a 256bit symmetric key
const symmetricKey = crypto.randomBytes(256);

//generate the public/private keys
let key = new rsa().generateKeyPair();
let publicKey = key.exportKey("public").toString('base64');
let privateKey = key.exportKey("private").toString('base64');

//get the string from the command line script
const stringBeforeEncoding = process.argv[2];

//Encrypt the string with symmetric key
let encryptedString = crypto.createCipher("aes-256-ctr",symmetricKey.toString('base64')).update(stringBeforeEncoding, "utf-8", 'hex');


// Encrypt the symmetric with the per key
let publicKeyHolder = new rsa()
publicKeyHolder.importKey(privateKey);
let symmetricKeyEncrypted = publicKeyHolder.encryptPrivate(symmetricKey, 'base64');

// printout the result

console.log(`the string a crypt: ${stringBeforeEncoding}`);
console.log(`the symmetric key before encryption: ${symmetricKey.toString('base64')}`);
console.log(`the public key: ${privateKey}`);
console.log('\n---------------------------------------------------------------------------\n');
console.log(`the string after encryption: ${encryptedString}`);
console.log(`the symmetric key after encryption: ${symmetricKeyEncrypted}`);

// verification of the result
let privateKeyHolder = new rsa()
privateKeyHolder.importKey(publicKey);
let decrypted = privateKeyHolder.decryptPublic(symmetricKeyEncrypted, 'utf8');
assert.equal(decrypted, symmetricKey, 'the keys are not equal');
let decryptedString = crypto.createCipher("aes-256-ctr",symmetricKey.toString('base64')).update(encryptedString, "hex", 'utf8');
assert.equal(decryptedString, stringBeforeEncoding, 'The tow strings are not equal');