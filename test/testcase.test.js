const keyConversion = require('../index');

//TODO
describe('key-convert', function () {
    
    it('secp256k1', function () {
        let type = keyConversion.handleKeyConvert('secp256k1');
        let msg = 'check is valid signature';
        
        //for random keys
        let randomKeys = type.generateKeys();
        console.log('generated keys: ');
        console.log(randomKeys);

        let pubDERRandomKey = type.convertPublicKeyToDer(randomKeys.publicKey);
        console.log('pubDERRandomKey: ' + pubDERRandomKey);
        let pubPEMRandomKey = type.convertPublicKeyToPem(randomKeys.publicKey);
        console.log('pubPEMRandomKey: ' + '\n' + pubPEMRandomKey);

        let privateDERRandomKey = type.convertPrivateKeyToDer(randomKeys.privateKey);
        console.log('privateDERRandomKey: ' + privateDERRandomKey);
        let privatePEMRandomKey = type.convertPrivateKeyToPem(randomKeys.privateKey);
        console.log('privatePEMRandomKey: ' + '\n' + privatePEMRandomKey);
        
        let signResult = type.sign(randomKeys.privateKey, msg);
        let isValid = type.checkIsValid(randomKeys.privateKey, msg, signResult.sig);
        console.log(isValid);
        
        console.log('******');
        // for given privateKey
        let privateKeyHex = '87d83da6f346b97c31b8db4b171b3b57fe42b3955b55be800cd5405780960e48';
        let ret = type.generateKeys(privateKeyHex)
        console.log('generated keys: ');
        console.log(ret);
        
        let pubDER = type.convertPublicKeyToDer(ret.publicKey);
        console.log('pubDER: ' + pubDER);
        let pubPEM = type.convertPublicKeyToPem(ret.publicKey);
        console.log('pubPEM: ' + '\n' + pubPEM);

        let privateDER = type.convertPrivateKeyToDer(ret.privateKey);
        console.log('privateDER: ' + privateDER);
        let privatePEM = type.convertPrivateKeyToPem(ret.privateKey);
        console.log('privatePEM: ' + '\n' + privatePEM);

        
        var signResult2 = type.sign(privateKeyHex, msg);
        let isValid2 = type.checkIsValid(privateKeyHex, msg, signResult2.sig);
        console.log(isValid2)
    });


    it('secp256r1', function () {
        let type = keyConversion.handleKeyConvert('secp256r1');
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
        console.log('privatePEM: ' + '\n' + privatePEM);
    });

    it('secp384r1', function () {
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
        console.log('privatePEM: ' + '\n' + privatePEM);

    });

    it('secp521r1 ', function () {
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
        console.log('privatePEM: ' + '\n' + privatePEM);
    });

});



