const asn1Define = require('../define');
const EC = require('elliptic').ec;

/**
 * generate random keys
 * @param type secp256k1/secp384r1/secp521r1
 * @param rawPublicKey
 */
function generateKeys() {
    var ec = new EC('secp256r1');
    var key = ec.genKeyPair();
    var privateK = key.getPrivate('hex');
    var publicK = key.getPublic('hex');
    var publicKCompact = key.getPublic(true, 'hex');
    return {
        type: "secp256r1",
        privateKey: privateK,
        publicKey: publicK,
        publicKCompact: publicKCompact
    }
}


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

    let ECParameters = asn1Define.ECParameters.encode({
        type: 'namedCurve',
        value: [1, 3, 132, 0, 10],
    }, 'der');

    let algorithmsType = {
        algorithm:  [1, 2, 840, 10045, 2, 1],
        parameters: ECParameters
    };

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
function convertPrivateKey(rawPrivateKey, format) {
    rawPrivateKey = rawPrivateKey.startsWith('0x')? rawPrivateKey.slice(2): rawPrivateKey;
    rawPrivateKey = Buffer.from(rawPrivateKey, 'hex');


    let keyPair;
    let rawPublicKey;
    let ec = new EC('secp256k1');
    keyPair = ec.keyFromPrivate(rawPrivateKey, 'hex');
    rawPublicKey = keyPair.getPublic('hex');
    rawPublicKey = Buffer.from(rawPublicKey, 'hex');

    let ECParameters = asn1Define.ECParameters.encode({
        type: 'namedCurve',
        value: [1, 3, 132, 0, 10],
    }, 'der');

    let algorithmsType = {
        algorithm:  [1, 2, 840, 10045, 2, 1],
        parameters: ECParameters
    };




    let publicKey = {
        unused: 0,
        data: rawPublicKey
    };




    let der = asn1Define.ECPrivateKey.encode({
                    version: 1,
                    privateKey: rawPrivateKey,
                    parameters:  [1, 3, 132, 0, 10],
                    publicKey: publicKey},
                'der')



    let pem = asn1Define.ECPrivateKey.encode({
                    version: 1,
                    privateKey: rawPrivateKey,
                    parameters:  [1, 3, 132, 0, 10],
                    publicKey: publicKey},
        'pem', {label: 'PRIVATE KEY'});


    if (format === 'DER') {
        return der.toString('hex')
    } else if (format === 'PEM') {
        return pem
    } else throw new Error('Invalid Key Format')
}


module.exports = {
    generateKeys: generateKeys,
    convertPublicKeyToDer: convertPublicKeyToDer,
    convertPublicKeyToPem: convertPublicKeyToPem,
    convertPrivateKeyToDer: convertPrivateKeyToDer,
    convertPrivateKeyToPem: convertPrivateKeyToPem
};
