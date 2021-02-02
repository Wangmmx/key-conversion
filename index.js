const util = require('./src/util');
const asn1Define = require('./src/define');
const elliptic = require('elliptic');
const EC = elliptic.ec;

/**
 *
 * @param type secp256k1/secp384r1/secp521r1
 */
function handleECParameters(type) {
    try {
        let parametersType = asn1Define.ECParameters.encode({
            type: 'namedCurve',
            value: util.ecOid[type],
        }, 'der');

        let algorithmsType = {
            algorithm:  util.ecAlgorithm[type],
            parameters: parametersType
        };
        return algorithmsType;
    } catch (e) {
        throw new Error('Type is invalid or need support later')
    }
}

/**
 * convert publicKey to DER format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 */
function convertPublicKeyToDer(type, rawPublicKey) {
   return convertPublicKey(type, rawPublicKey, 'DER');
}

/**
 * convert publicKey to PEM format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 */
function convertPublicKeyToPem(type, rawPublicKey) {
    return convertPublicKey(type, rawPublicKey, 'PEM');
}

/**
 *
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 * @param format DER/PEM
 */
function convertPublicKey(type, rawPublicKey, format) {
    rawPublicKey = rawPublicKey.startsWith('0x')? rawPublicKey.slice(2): rawPublicKey;
    rawPublicKey = Buffer.from(rawPublicKey, 'hex');

    let algorithmsType = handleECParameters(type);

    let publicKey = {
        unused: 0,
        data: rawPublicKey
    };

    let der =  asn1Define.PublicKeyInfo.encode({
        algorithm: algorithmsType,
        PublicKey: publicKey
    }, 'der');

    let pem = asn1Define.PublicKeyInfo.encode({
        algorithm: algorithmsType,
        PublicKey: publicKey
    }, 'pem', {label: 'PUBLIC KEY'});

    if (format === 'DER') {
        return der.toString('hex')
    } else if (format === 'PEM') {
        return pem
    } else throw new Error('Invalid Key Format')
}


/**
 * convert PrivateKey to DER format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPrivateKey
 */
function convertPrivateKeyToDer(type, rawPrivateKey) {
    return convertPrivateKey(type, rawPrivateKey, 'DER');
}

/**
 * convert PrivateKey to PEM format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPrivateKe
 */
function convertPrivateKeyToPem(type, rawPrivateKey) {
    return convertPrivateKey(type, rawPrivateKey, 'PEM');
}

/**
 *
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPrivateKe
 * @param format DER/PEM
 */
function convertPrivateKey(type, rawPrivateKey, format) {
    rawPrivateKey = rawPrivateKey.startsWith('0x')? rawPrivateKey.slice(2): rawPrivateKey;
    rawPrivateKey = Buffer.from(rawPrivateKey, 'hex');


    let keyPair;
    let rawPublicKey;
    switch (type) {
        case 'secp256k1':
            keyPair = this.options.curve.keyFromPrivate(privateKey, 'hex');
            break;
        case 'secp384r1':
            let ecdsaCurve = elliptic.curves.p384;
            let ecdsa = new EC(ecdsaCurve);
            keyPair = ecdsa.keyFromPrivate(rawPrivateKey, 'hex');
            rawPublicKey = keyPair.getPublic('hex');
            rawPublicKey = Buffer.from(rawPublicKey, 'hex');
            break;
        case 'secp521r1':
            keyPair = this.options.curve.keyFromPrivate(privateKey, 'hex');
            break;
    }

    let algorithmsType = handleECParameters(type);


    let publicKey = {
        unused: 0,
        data: rawPublicKey
    };

    let der =  asn1Define.PrivateKeyInfo.encode({
        version: 0,
        privateKeyAlgorithm: algorithmsType,
        privateKey:
            asn1Define.ECPrivateKey.encode({
                    version: 1,
                    privateKey: rawPrivateKey,
                    publicKey: publicKey},
                'der')
    }, 'der');

    let pem =  asn1Define.PrivateKeyInfo.encode({
        version: 0,
        privateKeyAlgorithm: algorithmsType,
        privateKey:
            asn1Define.ECPrivateKey.encode({
                    version: 1,
                    privateKey: rawPrivateKey,
                    publicKey: publicKey},
                'der')
    }, 'pem', {label: 'PRIVATE KEY'});


    if (format === 'DER') {
        return der.toString('hex')
    } else if (format === 'PEM') {
        return pem
    } else throw new Error('Invalid Key Format')
}


module.exports = {
    convertPublicKeyToDer: convertPublicKeyToDer,
    convertPublicKeyToPem: convertPublicKeyToPem,
    convertPrivateKeyToDer: convertPrivateKeyToDer,
    convertPrivateKeyToPem: convertPrivateKeyToPem
};
