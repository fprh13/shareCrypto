// const fs = require('fs');
// const pki = require('node-forge');

// fs.readFile('rootCert.pem', 'utf8', function (err, data) {
//   if (err) {
//     return console.log(err);
//   }
//   console.log(data);
//   let cert = pki.certificateFromPem(data);
//   let publickey = cert.publicKey;
//   console.log(publikey);
// });

// let fs = require('fs');

// console.log("인증서를 파일에서 읽어오기");
// fs.readFile('cert.pem', 'utf8', function (err, data) {
//   if (err) {
//     return console.log(err);
//   }
//   console.log(data);
//   let cert = pki.certificateFromPem(data);
//   let pub = cert.publicKey;
//   console.log(pki.publicKeyToPem(cert.publicKey));
// });

// 동기식 읽어오기
// let

//아래는 피피티 내용 위는 하다가 포기한 코드들

var forge = require('node-forge');
var fs = require('fs');
var pki = forge.pki;
var user = 'userB'; // 사용자명 설정
// 1. CA 개인키와 인증서를 파일에서 읽어오기
var caCertPem = fs.readFileSync('rootCert.pem', 'utf8');
var caPrivateKeyPem = fs.readFileSync('rootPrivateKey.pem', 'utf8');
var caCert = pki.certificateFromPem(caCertPem);
var caPrivateKey = pki.privateKeyFromPem(caPrivateKeyPem);
var verified = caCert.verify(caCert);
console.log('CA인증서 유효성 검증: ' + verified);
// ------------------------------
// 2. 사용자 키쌍 생성
var keys = pki.rsa.generateKeyPair(2048);
// 3. 사용자 개인키를 파일로 저장
console.log(pki.privateKeyToPem(keys.privateKey));
fs.writeFileSync(user + 'PrivateKey.pem', pki.privateKeyToPem(keys.privateKey));
console.log('사용자 개인키 저장 - ' + user + 'PrivateKey.pem \n');
// 4. 사용자 인증서 객체 생성
var cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

// 5. 사용자 정보 설정
var attrs = [
  {
    name: 'commonName', // 사용자명
    //shortName: 'CN',
    value: user,
  },
  {
    name: 'countryName', // 국가
    //shortName: 'C',
    value: 'KR',
  },
  {
    name: 'stateOrProvinceName', // 주, 지역
    //shortName: 'RT',
    value: 'Gyeonggi-do',
  },
  {
    name: 'localityName', // 도시명
    //shortName: 'L',
    value: 'Goyang-si',
  },
  {
    name: 'organizationName', // 기관명
    //shortName: 'O',
    value: 'Joongbu Univ.',
  },
  {
    name: 'organizationalUnitName', // 부서명
    //shortName: 'OU',
    value: 'Dept. of Information Security',
  },
];
cert.setSubject(attrs);

// 6. CA 정보 설정. 인증서에서 읽어와서 자동 설정
var caAttrs = [
  {
    name: 'commonName', // shortName: 'CN',
    value: caCert.subject.getField('CN').value,
  },
  {
    name: 'countryName', //  shortName: 'C',
    value: caCert.subject.getField('C').value,
  },
  {
    name: 'stateOrProvinceName', //  shortName: 'ST',
    value: caCert.subject.getField('ST').value,
  },
  {
    name: 'localityName', // shortName: 'L',
    value: caCert.subject.getField('L').value,
  },
  {
    name: 'organizationName', //  shortName: 'O',
    value: caCert.subject.getField('O').value,
  },
  {
    name: 'organizationalUnitName', //  shortName: 'OU',
    value: caCert.subject.getField('OU').value,
  },
];
cert.setIssuer(caAttrs);

// 7. 확장영역 설정
cert.setExtensions([
  {
    name: 'basicConstraints',
    cA: true,
  },
  {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true,
  },
  {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  },
  {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true,
  },
  {
    name: 'subjectAltName',
    altNames: [
      {
        type: 6, // URI
        value: 'http://example.org/webid#me',
      },
      {
        type: 7, // IP
        ip: '127.0.0.1',
      },
    ],
  },
  {
    name: 'subjectKeyIdentifier',
  },
]);

// 8. CA가 서명하여 사용자 인증서 생성
cert.sign(caPrivateKey); // CA 개인키로 서명
console.log('사용자 인증서 생성');
console.log(pki.certificateToPem(cert));
// 9. 사용자 인증서 검증
var verified = caCert.verify(cert);
console.log('사용자 인증서 검증: ' + verified);
// 10. 사용자 인증서 저장
fs.writeFileSync(user + 'Cert.pem', pki.certificateToPem(cert));
console.log('사용자 인증서 저장 - ' + user + 'Cert.pem');
