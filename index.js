const Type = require('./src/type/index');



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
 * @param rawPublicKey
 */
function convertPublicKeyToPem(rawPublicKey) {
    return convertPublicKey(rawPublicKey, 'PEM');
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
    return convertPrivateKey(rawPrivateKey, 'PEM');
}
/**
 *
 * @param type secp256k1/secp256r1/secp384r1/secp521r1
 */
function handleKeyConvert(type) {
        switch (type) {
            case 'secp256k1':
                return Type.secp256k1Type;
            case 'secp256r1':
                return Type.secp256r1Type;
            case 'secp384r1':
                return Type.secp384r1Type;
            case 'secp521r1':
                return Type.secp521r1Type;
        }
    throw new Error('Type is invalid or need support later')
}


module.exports = {
    handleKeyConvert: handleKeyConvert
};
