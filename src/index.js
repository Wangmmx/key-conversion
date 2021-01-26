const util = require('./util');
const asn1Define = require('./define')


/**
 *
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 */
function convertPublicKeyToPem(type, rawPublicKey) {
    if (type === 'secp256k1') {
        throw new Error('Will support ASAP: ' + type)
    }  else if (type === 'secp384r1') {
        let parameters384 = asn1Define.ECParameters.encode({
            type: 'namedCurve',
            value: util.ecOid.secp384r1,
        }, 'der');

        let algorithms384 = {
            algorithm:  util.ecAlgorithm.secp384r1,
            parameters: parameters384
        };


        rawPublicKey = rawPublicKey.startsWith('0x')? rawPublicKey.slice(2): rawPublicKey;
        rawPublicKey = Buffer.from(rawPublicKey, 'hex');

        let publicKey = {
            unused: 0,
            data: rawPublicKey
        };

        return asn1Define.PublicKeyInfo.encode({
            algorithm: algorithms384,
            PublicKey: publicKey
        }, 'pem', {label: 'PUBLIC KEY'})

    } else if (type === 'secp521r1') {
        throw new Error('Will support ASAP: ' + type)

    } else {
        throw new Error('Not support this type yet: ' + type)
    }

}

/**
 *
 * @param type
 * @param key
 */
function convertPrivateKeyToPem(type, rawPublicKey, rawPrivateKey) {
    if (type === 'secp256k1') {
        throw new Error('Will support ASAP: ' + type)
    }  else if (type === 'secp384r1') {
        let parameters384 = asn1Define.ECParameters.encode({
            type: 'namedCurve',
            value: util.ecOid.secp384r1,
        }, 'der');

        let algorithms384 = {
            algorithm:  util.ecAlgorithm.secp384r1,
            parameters: parameters384
        };

        rawPublicKey = rawPublicKey.startsWith('0x')? rawPublicKey.slice(2): rawPublicKey;
        rawPublicKey = Buffer.from(rawPublicKey, 'hex');

        rawPrivateKey = rawPrivateKey.startsWith('0x')? rawPrivateKey.slice(2): rawPrivateKey;
        rawPrivateKey = Buffer.from(rawPrivateKey, 'hex');

        let publicKey = {
            unused: 0,
            data: rawPublicKey
        };

        return asn1Define.PrivateKeyInfo.encode({
            version: 0,
            privateKeyAlgorithm: algorithms384,
            privateKey:
                asn1Define.ECPrivateKey.encode({
                        version: 1,
                        privateKey: rawPrivateKey,
                        publicKey: publicKey},
                    'der')
        }, 'pem', {label: 'PRIVATE KEY'});

    } else if (type === 'secp521r1') {
        throw new Error('Will support ASAP: ' + type)
    } else {
        throw new Error('Not support this type yet: ' + type)
    }
}


module.exports = {
    convertPublicKeyToPem: convertPublicKeyToPem,
    convertPrivateKeyToPem: convertPrivateKeyToPem
};




