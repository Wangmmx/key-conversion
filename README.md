# key-conversion
key conversion tools for EC keys  
Support secp256k1, secp384r1, secp521r1 elliptic curve key conversion  
Can be converted from rawKey to hexadecimal DER format and PEM format


Currently only supports secp384r1
Usage:
```
var keyConversion = require('key-conversion');
let type = keyConversion.handleKeyConvert('secp256k1');
let ret = type.generateKeys()
console.log('generated keys: ')
console.log(ret)

let pubDER = type.convertPublicKeyToDer(ret.publicKey);
console.log('pubDER: ' + pubDER);
let pubPEM = type.convertPublicKeyToPem(ret.publicKey);
console.log('pubPEM: ' + '\n' + pubPEM);

let privateDER = type.convertPrivateKeyToDer(ret.privateKey);
console.log('privateDER: ' + privateDER);
let privatePEM = type.convertPrivateKeyToPem(ret.privateKey);
console.log('privatePEM: ' + '\n' + privatePEM);    });

secp256k1 can be replaced by 'secp256r1', 'secp384r1', 'secp521r1'

```
Release Notes:  
1.0.0  
Add function to convert raw key to PEM format only for p384

1.0.1   
Update README and add Usage sample  

2.0.0  
Refactor code, change the Usage  
Support convert raw key to DER and PEM both for p384
