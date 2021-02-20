// const keyConversion = require('../index');

// let rawPub = '04....';
// let pubType = 'secp384r1'; //'secp384r1' or'secp521r1'
// let pubDER = keyConversion.convertPublicKeyToDer(pubType, rawPub);
// var pubPEM = keyConversion.convertPublicKeyToPem(pubType, rawPub);
// console.log('pubDer', '\n', pubDER, '\n', 'pubPem', '\n', pubPEM);


// let rawPrivate = 'e7...';
// let privateType = 'secp384r1'; //'secp384r1' or'secp521r1'
// let privateDER = keyConversion.convertPrivateKeyToDer(privateType, rawPrivate);
// var privatePEM = keyConversion.convertPrivateKeyToPem(privateType, rawPrivate);
// console.log('privateDer', '\n', privateDER, '\n', 'privatePem', '\n', privatePEM);

// var rawPrivate = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b';
// let privateDER = keyConversion.convertPrivateKeyToDer('secp256k1', rawPrivate);
// var privatePEM = keyConversion.convertPrivateKeyToPem('secp256k1', rawPrivate);
// console.log('privateDer', '\n', privateDER, '\n', 'privatePem', '\n', privatePEM);
//
//

const keyConversion = require('../index');
var Type = keyConversion.handleKeyConvert('secp384r1');
console.log(Type);

// let ret1 = Type.convertPublicKeyToPem();
let ret2 = Type.convertPrivateKeyToPem('e7c3a3fbb2c5ce20562d305ee91c8ebe79291fdc6cf82af8de147d08d5d0b0a0c016090156c20dc6dacc3cddeb882c66');
console.log(ret2)

var Type2 = keyConversion.handleKeyConvert('secp256k1');
console.log(Type2);


let ret3 = Type2.convertPrivateKeyToPem('844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b');
let ret4 = Type2.convertPrivateKeyToDer('844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b');
console.log(ret3)
console.log(ret4)
