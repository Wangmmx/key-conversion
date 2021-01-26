# key-conversion
key conversion tools for privateKey and PublicKey, RAW convert to DER, DER convert to PEM, and so on


Usage:
```
var keyConversion = require('key-conversion');

var pubKey = '04349343...'
var pubPEM = keyConversion.convertPublicKeyToPem('secp384r1', pubKey));
var pubPEM = keyConversion.convertPublicKeyToPem('secp256k1', pubKey));
var pubPEM = keyConversion.convertPublicKeyToPem('secp521r1', pubKey));

var privateKey = 'e3....';
var privatePEM = keyConversion.convertPrivateKeyToPem('secp384r1', pubKey, privateKey))
var privatePEM = keyConversion.convertPrivateKeyToPem('secp521r1', pubKey, privateKey))
var privatePEM = keyConversion.convertPrivateKeyToPem('secp256k1', pubKey, privateKey))

```

secp256k1 and secp521r1 will be support later, and DER to PEM support later
