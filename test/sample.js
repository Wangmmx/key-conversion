const keyConversion = require('../index');


let rawPub = '04....';
let pubType = 'secp384r1'; //'secp384r1' or'secp521r1'
let pubDER = keyConversion.convertPublicKeyToDer(pubType, rawPub);
var pubPEM = keyConversion.convertPublicKeyToPem(pubType, rawPub);
console.log('pubDer', '\n', pubDER, '\n', 'pubPem', '\n', pubPEM);


let rawPrivate = 'e7...';
let privateType = 'secp384r1'; //'secp384r1' or'secp521r1'
let privateDER = keyConversion.convertPrivateKeyToDer(privateType, rawPrivate);
var privatePEM = keyConversion.convertPrivateKeyToPem(privateType, rawPrivate);
console.log('privateDer', '\n', privateDER, '\n', 'privatePem', '\n', privatePEM);



