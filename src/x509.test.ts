import { describe, expect, test } from 'vitest';
import { DateTime } from 'luxon';
import { buildChildCert, buildRootCert } from './x509';

describe('useX509CertGenerator', () => {

    test(`Test X509CertificateGenerator.create self signed certificate`, async () => {
        const rootCert = await buildRootCert();

        const ok = await rootCert.cert.verify({ date: DateTime.now().toJSDate() });
        expect(ok).toStrictEqual(true);

        const validAfter = await rootCert.cert.verify({ date: DateTime.now().plus({ days: 2 }).toJSDate() });
        expect(validAfter).toBeFalsy();

        const validBefore = await rootCert.cert.verify({ date: DateTime.now().minus({ day: 1 }).toJSDate() });
        expect(validBefore).toBeFalsy();
    });

    test(`Child cert should be verifiable using parent`, async () => {

        const rootCert = await buildRootCert();
        const childCert = await buildChildCert(rootCert);

        const ok = await childCert.cert.verify(rootCert.cert);

        expect(ok).toBeTruthy();

        const validAfter = await childCert.cert.verify({ date: DateTime.now().plus({ days: 366 }).toJSDate() });
        expect(validAfter).toBeFalsy();

        const validBefore = await childCert.cert.verify({ date: DateTime.now().minus({ day: 1 }).toJSDate() });
        expect(validBefore).toBeFalsy();
    });

    // test(`Child certificate should not be verifiable using another root cert`, async () => {
    //     const rootCert = await buildRootCert();
    //     const childCert = await buildChildCert(rootCert);

    //     expect(await childCert.cert.verify({
    //         date: new Date("2020/01/01 12:00"),
    //         publicKey: await rootCert.cert.publicKey.export()
    //     })).toBeFalsy();
    // });
});
