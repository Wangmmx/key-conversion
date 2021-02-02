# key-conversion
key conversion tools for EC keys  
Support secp256k1, secp384r1, secp521r1 elliptic curve key conversion  
Can be converted from rawKey to hexadecimal DER format and PEM format


Currently only supports secp384r1
Usage:
```
var keyConversion = require('key-conversion');
let rawPub = '04....';
let pubType = 'secp384r1'; //'secp384r1' or'secp521r1'
let pubDER = keyConversion.convertPublicKeyToDer(pubType, rawPub);
var pubPEM = keyConversion.convertPublicKeyToPem(pubType, rawPub);


let rawPrivate = 'e7...';
let privateType = 'secp384r1'; //'secp384r1' or'secp521r1'
let privateDER = keyConversion.convertPrivateKeyToDer(privateType, rawPrivate);
var privatePEM = keyConversion.convertPrivateKeyToPem(privateType, rawPrivate);


```
Release Notes:  
1.0.0  
Add function to convert raw key to PEM format only for p384

1.0.1   
Update README and add Usage sample  

2.0.0  
Refactor code, change the Usage  
Support convert raw key to DER and PEM both for p384
