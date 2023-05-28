const forge = require('node-forge');
const fs = require('fs');
const pki = forge.pki;
const rsa = forge.pki.rsa;

//1. RSA 계정 생성
const keyPair = pki.rsa.generateKeyPair(2048);
// console.log(keyPair);
const privatekey = keyPair.privateKey;
const publickey = keyPair.publicKey;
console.log(pki.privateKeyToPem(privatekey));
console.log(pki.publicKeyToPem(publickey));

// 인증서 객체 생성
const cert = pki.createCertificate();

// 각종 필드 정보 입력
cert.publicKey = publickey;
cert.serialNumber = '001';
cert.validity.notBefore = new Date();
cert.validity.notAfter.setUTCFullYear(
  cert.validity.notBefore.getFullYear() + 1
);

// 사용자 정보 설정
let attrs = [
  {
    name: 'commonName', //사용자명
    value: 'example.org',
  },
  {
    name: 'countryName',
    value: 'KR',
  },
  {
    name: 'stateOrProvinceName', //주 지역
    value: 'Gyenggi-do',
  },
  {
    name: 'localityName', //도시명
    value: 'Goyang-si',
  },
  {
    name: 'organizationName',
    value: 'joongbu',
  },
  {
    name: 'organizationalUnitName',
    value: 'imformation Secirity',
  },
];
cert.setSubject(attrs);
cert.setIssuer(attrs);

let exts = [
  {
    name: 'basicConstraints',
    cA: true, // 인증기관의 인증서임을 나타냄
  },
  {
    name: 'keyUsage', // 키용도 설정
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true,
  },
  {
    name: 'extKeyUsage', // 확장 키용도 설정
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true,
  },
  {
    name: 'nsCertType', // 인증서 타입
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true,
  },
  {
    name: 'subjectAltName', // 주체 별도 정보
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
    // 주체 키 식별자
    name: 'subjectKeyIdentifier',
  },
];
cert.setExtensions(exts);

// 인증서 객체를 개인키로 서명
cert.sign(privatekey);

// 인증서 객체를 pem 형식으로 출력
let certPem = pki.certificateToPem(cert);
console.log(certPem);

// 인증서 유gy성 검증

let result = cert.verify(cert);
console.log('인증서 유효성: ', result);

// 인증서와 개인키를 파일로 저장하기

fs.writeFile(
  'rootPublicKey.pem',
  pki.publicKeyToPem(publickey),
  function (err) {
    if (err) {
      return console.log(err);
    }
  }
);
fs.writeFile(
  'rootPrivateKey.pem',
  pki.privateKeyToPem(privatekey),
  function (err) {
    if (err) {
      return console.log(err);
    }
  }
);
fs.writeFile('rootCert.pem', pki.certificateToPem(cert), function (err) {
  if (err) {
    return console.log(err);
  }
});
