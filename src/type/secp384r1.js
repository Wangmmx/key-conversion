const util = require('../util');
const asn1Define = require('../define');
const elliptic = require('elliptic');
const EC = elliptic.ec;

/**
 * convert publicKey to DER format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 */
function convertPublicKeyToDer(rawPublicKey) {
    return convertPublicKey(rawPublicKey, 'DER');
}

/**
 * convert publicKey to PEM format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 */
function convertPublicKeyToPem(rawPublicKey) {
    return convertPublicKey(rawPublicKey, 'PEM');
}

/**
 *
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 * @param format DER/PEM
 */
function convertPublicKey(rawPublicKey, format) {
    rawPublicKey = rawPublicKey.startsWith('0x')? rawPublicKey.slice(2): rawPublicKey;
    rawPublicKey = Buffer.from(rawPublicKey, 'hex');

    let parametersType = asn1Define.ECParameters.encode({
        type: 'namedCurve',
        value: util.ecOid['secp384r1'],
    }, 'der');

    let algorithmsType = {
        algorithm:  util.ecAlgorithm['secp384r1'],
        parameters: parametersType
    };

    let publicKey = {
        unused: 0,
        data: rawPublicKey
    };

    let der =  asn1Define.PublicKeyInfo.encode({
        algorithm: util.ecAlgorithm['secp384r1'],
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
function convertPrivateKeyToDer(rawPrivateKey) {
    return convertPrivateKey(rawPrivateKey, 'DER');
}

/**
 * convert PrivateKey to PEM format
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPrivateKe
 */
function convertPrivateKeyToPem(rawPrivateKey) {
    return convertPrivateKey( rawPrivateKey, 'PEM');
}

/**
 *
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPrivateKe
 * @param format DER/PEM
 */
function convertPrivateKey (rawPrivateKey, format) {
    rawPrivateKey = rawPrivateKey.startsWith('0x')? rawPrivateKey.slice(2): rawPrivateKey;
    rawPrivateKey = Buffer.from(rawPrivateKey, 'hex');


    let keyPair;
    let rawPublicKey;
    let ec;

            let ecdsaCurve = elliptic.curves.p384;
            ec = new EC(ecdsaCurve);
            keyPair = ec.keyFromPrivate(rawPrivateKey, 'hex');
            rawPublicKey = keyPair.getPublic('hex');
    rawPublicKey = Buffer.from(rawPublicKey, 'hex');



let parametersType = asn1Define.ECParameters.encode({
    type: 'namedCurve',
    value: util.ecOid['secp384r1'],
}, 'der');

let algorithmsType = {
    algorithm:  util.ecAlgorithm['secp384r1'],
    parameters: parametersType
};


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
