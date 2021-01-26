let ecOid = {
    secp256k1: [1, 2, 840, 10045, 3, 1, 7],//[1, 3, 132, 0, 10],
    secp384r1: [1, 3, 132, 0, 34],
    secp521r1: [1, 3, 132, 0, 35]
};


let ecAlgorithm = {
    secp256k1: [1, 2, 840, 10045, 2, 1],
    secp384r1: [1, 2, 840, 10045, 2, 1],
    secp521r1: [1, 2, 840, 10045, 2, 1]
};

module.exports = {
    ecOid: ecOid,
    ecAlgorithm: ecAlgorithm
};



