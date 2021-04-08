/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import CasperApp from "@zondax/ledger-casper";

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve("../app/output/app_s.elf");
const APP_PATH_X = Resolve("../app/output/app_x.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"

var simOptions = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`,
    X11: false
};

let models = [
    ['S', {model: 'nanos', prefix: 'S', path: APP_PATH_S}],
    ['X', {model: 'nanox', prefix: 'X', path: APP_PATH_X}]
]

jest.setTimeout(60000)

describe('Standard', function () {
    test.each(models)('can start and stop container (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
        } finally {
            await sim.close();
        }
    });

    test.each(models)('main menu (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-mainmenu`, 3);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('get app version (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());
            const resp = await app.getVersion();

            console.log(resp);

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");
            expect(resp).toHaveProperty("testMode");
            expect(resp).toHaveProperty("major");
            expect(resp).toHaveProperty("minor");
            expect(resp).toHaveProperty("patch");
        } finally {
            await sim.close();
        }
    });

    test.each(models)('get address (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const resp = await app.getAddressAndPubKey("m/44'/506'/0'/0/0");

            console.log(resp)

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            expect(resp.publicKey.toString('hex')).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('show address (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const respRequest = app.showAddressAndPubKey("m/44'/506'/0'/0/0");

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-show_address`, model === "nanos" ? 2 : 3);

            const resp = await respRequest;

            console.log(resp)

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            expect(resp.publicKey.toString('hex')).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const txBlobStr = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee36000000000001000000000000004811966d37fe5674a8af4001884ea0d9042d1c06668da0c963769c3a01ebd08f0100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c657725c391ccf5053bbe48b6a99843ceef4b342e72cc1daf195d1bcfa8d805f0d8020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 6 : 7);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            // const expected_preHash = "0a69632d72657175657374bf5bae8c2b6be8103a070e6d2240c18788c10a94ba68990f8c7e7acecb8b8c34";
            // expect(signatureResponse.preSignHash.toString('hex')).toEqual(expected_preHash);
            //
            // const expected_hash = "084544f8f1852065408e18c5bc595e07c49e44085728833a822b24487eb4e191";
            // let hash = sha256.hex(signatureResponse.preSignHash);
            // expect(hash).toEqual(expected_hash);
            //
            // const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString(), 'hex'))
            // expect(pk.byteLength).toEqual(65);
            // const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            // const signature = Uint8Array.from(signatureResponse.signatureRS);
            // //const signature = secp256k1.signatureImport(Uint8Array.from(signatureResponse.signatureDER));
            // expect(signature.byteLength).toEqual(64);
            //
            // const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            // expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });
});
