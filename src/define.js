const asn1 = require('asn1.js');


let Version = asn1.define('Version', function() {
    this.int();
});

let AlgorithmIdentifier = asn1.define('AlgorithmIdentifer', function() {
    this.seq().obj(
        this.key('algorithm').objid(),
        this.key('parameters').optional().any()
    );
});

let PublicKeyInfo = asn1.define('PublicKeyInfo',  function() {
    this.seq().obj(
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('PublicKey').bitstr()
    );
});


let PrivateKeyInfo = asn1.define('PrivateKeyInfo', function() {
    this.seq().obj(
        this.key('version').use(Version),
        this.key('privateKeyAlgorithm').use(AlgorithmIdentifier),
        this.key('privateKey').octstr(),
        this.key('attributes').optional().any()
    );
});

let ECPrivateKeyP384 = asn1.define('ECPrivateKeyP384', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('privateKey').octstr(),
        this.key('publicKey').explicit(1).optional().bitstr()
    );
});



let ECPrivateKey = asn1.define('ECPrivateKey', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('privateKey').octstr(),
        this.key('parameters').explicit(0).objid().optional(),
        this.key('publicKey').explicit(1).bitstr().optional()
    );
});



let ECParameters = asn1.define('ECParameters', function() {
    this.choice({
        namedCurve: this.objid()
    });
});




module.exports = {
    Version: Version,
    AlgorithmIdentifier: AlgorithmIdentifier,
    PublicKeyInfo: PublicKeyInfo,
    PrivateKeyInfo: PrivateKeyInfo,
    ECPrivateKeyP384: ECPrivateKeyP384,
    ECPrivateKey: ECPrivateKey,
    ECParameters: ECParameters
};


