const forge = require('node-forge');
const fs = require('fs');
const pki = forge.pki;

const userA = 'userA'; //송신자
const userB = 'userB'; //수신자

//1. 송신자가 전자본투 생성
const userAPrivateKeyPem = fs.readFileSync('userAPrivateKey.pem', 'utf8');
const userAPrivateKey = pki.privateKeyFromPem(userAPrivateKeyPem);
// 1.2 수신자 B의 인증서 읽어옴
const userBCertPem = fs.readFileSync('userBCert.pem', 'utf8');
const userBCert = pki.certificateFromPem(userBCertPem);
const userBPublicKey = userBCert.publicKey;
// 1.3 인증기관의 인증서 읽어옴
let caCertPem = fs.readFileSync('rootCert.pem', 'utf8');
let caCert = pki.certificateFromPem(caCertPem);
// 1.4 수신자 B의 인증서 유효성 검증
let verifiedB = caCert.verify(userBCert);
console.log('1.4 수신자 B의 인증서 검증: ' + verifiedB);
// 1.5 송신자 A: 메시지에 대한 전자서명 생성
let message = 'Hello world. 안녕하세요.';
let md = forge.md.sha1.create();
md.update(message, 'utf8');
let signature = userAPrivateKey.sign(md);
let signatureHex = forge.util.bytesToHex(signature);
let messageObject = {
  msg: message,
  sigHex: signatureHex,
};
let messageString = JSON.stringify(messageObject);
console.log('1.5 JSON Message string:\n' + messageString);

// 1.6 송신자 A: 세션키로 메시지+전자서명을 암호화
let keySize = 16; // 16 => AES-128, 24 => AES-192, 32 => AES-256
let ivSize = 16;
let key = forge.random.getBytesSync(keySize);
let iv = forge.random.getBytesSync(ivSize);
let keyObject = {
  key: key,
  iv: iv,
};
let keyString = JSON.stringify(keyObject);
console.log('1.6 JSON key string: \n' + keyString);
let someBytes = forge.util.encodeUtf8(messageString);
let cipher = forge.cipher.createCipher('AES-CBC', key);
cipher.start({ iv: iv });
cipher.update(forge.util.createBuffer(someBytes));
cipher.finish();
let encrypted = cipher.output;
let encryptedMessageHex = forge.util.bytesToHex(encrypted);
console.log('1.6 encryptedMessageHex: \n' + encryptedMessageHex); // 1.7 세션키를 수신자 B의 공개키로 암호화
// console.log('RSA-OAEP');
let encryptedSessionKey = userBPublicKey.encrypt(keyString, 'RSA-OAEP');
let encryptedSessionKeyHex = forge.util.bytesToHex(encryptedSessionKey);
console.log('1.7 encryptedSessionKeyHex: \n' + encryptedSessionKeyHex);
