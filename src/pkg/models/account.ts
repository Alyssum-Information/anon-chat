import * as crypto from "crypto";

export class Account {
    publicKey: string
    privateKey?: string
    name?: string

    constructor(publicKey?: string, privateKey?: string, name?: string) {
        if (publicKey === undefined) {
            const newKeyPair = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });
            this.publicKey = newKeyPair.publicKey.toString();
            this.privateKey = newKeyPair.privateKey.toString();
        } else {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
        this.name = name
    }

    get id() {
        const hash = crypto.createHash('sha256')
        return hash.update(this.publicKey).digest('hex');
    }

    get publicKeyObj() {
        return crypto.createPublicKey(this.publicKey);
    }

    set publicKeyObj(value) {
        this.publicKey = value.export({
            type: 'spki',
            format: 'pem'
        }).toString();
    }

    get privateKeyObj() {
        return this.privateKey ? crypto.createPrivateKey(this.privateKey) : undefined;
    }

    set privateKeyObj(value) {
        this.privateKey = value?.export({
            type: 'pkcs8',
            format: 'pem'
        }).toString();
    }

    sign(data: string) {
        if (!this.privateKey) {
            throw new Error('No private key provided');
        }
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(data);
        return sign.sign(this.privateKey, 'hex');
    }

    verify(data: string, signature: string) {
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(data);
        return verify.verify(this.publicKey, signature, 'hex');
    }
}