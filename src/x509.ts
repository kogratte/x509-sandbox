import * as x509 from '@peculiar/x509';
import { DateTime } from 'luxon';
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const alg = {
    name: 'RSASSA-PKCS1-v1_5',
    hash: 'SHA-256',
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
};

export async function buildRootCert() {
    const keys: CryptoKeyPair = await crypto.subtle.generateKey(alg, false, ['sign', 'verify']);

    const tbs = {
        signingAlgorithm: alg,
        keys,
        extensions: [
            new x509.BasicConstraintsExtension(true, undefined, true),
            new x509.KeyUsagesExtension(
                x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.keyCertSign,
                true
            ),
            await x509.SubjectKeyIdentifierExtension.create(
                keys.publicKey,
                false,
                crypto
            ),
            await x509.AuthorityKeyIdentifierExtension.create(
                keys.publicKey,
                false,
                crypto
            ),
        ],
        serialNumber: DateTime.now().toMillis().toString(),
        name: "CN=Test",
        subject: "CN=Test",
        issuer: "CN=Test",
        notBefore: DateTime.now().minus({ hour: 1 }).toJSDate(),
        notAfter: DateTime.now().plus({ day: 1 }).toJSDate(),
    } as x509.X509CertificateCreateSelfSignedParams;

    const cert = await x509.X509CertificateGenerator.createSelfSigned(tbs, crypto);

    return { cert, keys };
};

export async function buildChildCert(rootCert: {
    cert: x509.X509Certificate,
    keys: CryptoKeyPair
}) {
    const intermediateKeys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    const intermediateCert = await x509.X509CertificateGenerator.create({
        signingKey: rootCert.keys.privateKey,
        publicKey: intermediateKeys.publicKey,
        signingAlgorithm: alg,
        serialNumber: DateTime.now().toMillis().toString(),
        subject: "CN=Intermediate",
        issuer: rootCert.cert.subject,
        notBefore: DateTime.now().minus({ hour: 1 }).toJSDate(),
        notAfter: DateTime.now().plus({ day: 1 }).toJSDate(),
    }, crypto);

    const leafKeys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    const leafCert = await x509.X509CertificateGenerator.create({
        signingKey: intermediateKeys.privateKey,
        publicKey: leafKeys.publicKey,
        signingAlgorithm: alg,
        serialNumber: DateTime.now().toMillis().toString(),
        subject: "CN=RouterCert",
        issuer: intermediateCert.subject,
        notBefore: DateTime.now().minus({ hour: 1 }).toJSDate(),
        notAfter: DateTime.now().plus({ day: 1 }).toJSDate(),
    }, crypto);

    return { cert: leafCert, keys: leafKeys };
}
