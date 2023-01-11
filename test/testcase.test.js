const keyConversion = require('../index');

//TODO
describe('key-convert', function () {
    
    it('secp256k1', function () {
        let type = keyConversion.handleKeyConvert('secp256k1');
        let ret = type.generateKeys('87d83da6f346b97c31b8db4b171b3b57fe42b3955b55be800cd5405780960e48')
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
        
        let isValid = type.checkIsValid('87d83da6f346b97c31b8db4b171b3b57fe42b3955b55be800cd5405780960e48', '3044022038a1ffaffaab01e9c0a8dc0cc1706a4764d4629513cd83f7c9f26de9f4b75175022043bc625bb871225fea9181fbce48a77a95f38759622fad2571cca30ae5c4a2f0')
        console.log(isValid)
        
        // console.log(Buffer.from('3044022038a1ffaffaab01e9c0a8dc0cc1706a4764d4629513cd83f7c9f26de9f4b75175022043bc625bb871225fea9181fbce48a77a95f38759622fad2571cca30ae5c4a2f0').toString('base64'))
        
        //MEUCIQCd+gMs8zKhd470LFrB7+LMF+nTkQ2GQwdTVc69L7Sd7AIgZOD5AVEkuwre639/nBShK1kmizSzcidkPCpxLBX0lQ4=
        //MEUCIQDa6tJmBKoD4PwQPyipCnaqkaJfNB1sAtSEBrsJZ1W4MgIgHSGPBTG/CQUAti01HrR7S+c0oVPgYBRe92kHeDCiKzM=
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



