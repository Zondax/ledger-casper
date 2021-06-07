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
import * as secp256k1 from "secp256k1";

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

            const respAddr = await app.getAddressAndPubKey("m/44'/506'/0'/0/0");
            console.log(respAddr)

            expect(respAddr.returnCode).toEqual(0x9000);
            expect(respAddr.errorMessage).toEqual("No errors");

            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";
            expect(respAddr.publicKey.toString('hex')).toEqual(expected_pk);

            const txBlobStr = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000002da6c76f011f893c38c1d0ac1927c4417e0a38ff6aacf27d156562cb4642ab30020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65745efa31877daaba4cb9ce55934fd83d4ec305418f1d25ba3d0bd25630c8d862e500000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f7572636522000000010202020202020202020202020202020202020202020202020202020202020202010d0c060000007461726765742000000001010101010101010101010101010101010101010101010101010101010101010f2000000001000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce553701a8cad8443504610e51a1f2448c8ab142a8fb32963f7701802c1cf1cf96d345031ec12e30ee513e9d969f94712edaff121b6f7023b086c96571efd477b8752b0d"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 11 : 12);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            // let hash = txBlob.slice(144,176);
            //
            // const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString('hex'), 'hex'))
            // expect(pk.byteLength).toEqual(33);
            // const digest = Uint8Array.from(Buffer.from(hash.toString('hex'), 'hex'));
            // const signature = Uint8Array.from(signatureResponse.signatureRS);
            // expect(signature.byteLength).toEqual(64);
            //
            // const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            // expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });


    test.each(models)('sign expert transfer(%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            // Enable expert mode
            console.log("Set expert mode")
            await sim.clickRight();
            await sim.clickBoth();
            await sim.clickLeft();

            // const respAddr = await app.getAddressAndPubKey("m/44'/506'/0'/0/0");
            // console.log(respAddr)
            //
            // expect(respAddr.returnCode).toEqual(0x9000);
            // expect(respAddr.errorMessage).toEqual("No errors");
            //
            // const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";
            // expect(respAddr.publicKey.toString('hex')).toEqual(expected_pk);

            const txBlobStr = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000002da6c76f011f893c38c1d0ac1927c4417e0a38ff6aacf27d156562cb4642ab30020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65745efa31877daaba4cb9ce55934fd83d4ec305418f1d25ba3d0bd25630c8d862e500000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f7572636522000000010202020202020202020202020202020202020202020202020202020202020202010d0c060000007461726765742000000001010101010101010101010101010101010101010101010101010101010101010f2000000001000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce553701a8cad8443504610e51a1f2448c8ab142a8fb32963f7701802c1cf1cf96d345031ec12e30ee513e9d969f94712edaff121b6f7023b086c96571efd477b8752b0d"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_expert_transfer`, model === "nanos" ? 21 : 21);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            // let hash = txBlob.slice(144,176);
            //
            // const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString('hex'), 'hex'))
            // expect(pk.byteLength).toEqual(33);
            // const digest = Uint8Array.from(Buffer.from(hash.toString('hex'), 'hex'));
            // const signature = Uint8Array.from(signatureResponse.signatureRS);
            // expect(signature.byteLength).toEqual(64);
            //
            // const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            // expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });
});