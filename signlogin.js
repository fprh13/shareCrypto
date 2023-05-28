const forge = require('node-forge');
const fs = require('fs');
const pki = forge.pki;
// 1. 사용자 A가 서버에게 서명된 로그인 요청 메시지를 전송
// 1.1 사용자 A의 개인키 읽어옴
var userAPrivateKeyPem = fs.readFileSync('userAPrivateKey.pem', 'utf8');
var userAPrivateKey = pki.privateKeyFromPem(userAPrivateKeyPem);
// 1.2 서명된 로그인 메시지 생성
var ID = 'userA';
var time = new Date().getTime();
var md = forge.md.sha1.create();
md.update(ID + time, 'utf8');
var signature = userAPrivateKey.sign(md);
var signatureHex = forge.util.bytesToHex(signature);
// 1.3 <ID, time, signature>를 로그인 메시지로 서버에 전송
console.log('사용자 A측');
console.log('ID: ' + ID);
console.log('현재시간: ' + time);
console.log('Signature: ' + signatureHex);

// 2. 서버가 사용자의 로그인 요청 메시지 검증
// 2.1 사용자 A로부터 <ID, time, signature>를 수신
console.log('서버측');
// 2.2 사용자 계정 DB로부터 사용자 A의 인증서 읽어옴
var userACertPem = fs.readFileSync('userACert.pem', 'utf8');
var userACert = pki.certificateFromPem(userACertPem);
// 2.3 인증기관의 인증서 읽어옴
var caCertPem = fs.readFileSync('rootCert.pem', 'utf8');
var caCert = pki.certificateFromPem(caCertPem);
// 2.4 사용자 A의 인증서 검증
var verified1 = caCert.verify(userACert);
console.log('사용자 A의 인증서 검증: ' + verified1);
// 2.5 전자서명 검증
var userAPublicKey = userACert.publicKey;
var md = forge.md.sha1.create();
md.update(ID + time, 'utf8');
var verified2 = userAPublicKey.verify(md.digest().bytes(), signature);
console.log('서명의 유효성 검증: ' + verified2);
var timeS = new Date().getTime();
console.log('서버 현재시간: ' + timeS);
var timeDiff = timeS - time;
console.log('현재시간의 유효성 검증: ' + timeDiff / 1000 + '초');
var verified3;
if (timeDiff < 1000) verified3 = true;
if (verified1 === true && verified2 === true && verified3 === true) {
  console.log('로그인 허용');
} else {
  console.log('로그인 거부');
}
