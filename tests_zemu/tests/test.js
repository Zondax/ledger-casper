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

const sha256 = require('js-sha256')

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
            const expected_address = "02028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            expect(resp.publicKey.toString('hex')).toEqual(expected_pk);
            expect(resp.address.toString('hex')).toEqual(expected_address);
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

            const txBlobStr = "013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000080ee3600000000000200000000000000e1247fa76cf3ea60f702267f4f45862ac168ee1eff95e006283125f392ab68cf0a0000000000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909070000006d61696e6e6574b82be13943ab8ff905984dd9c506caf9d4d98cdaf174589040e016f564cdaf0600000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f7572636522000000010202020202020202020202020202020202020202020202020202020202020202010d0c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000001000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290124c76ebd6ade72fbc7c638e901476f63566c49a7a97c47ab906d5c6f7fe9a19bd9fbebce567594ad712217c21cef778a2eebef94e1b203b21fc58a27ca1a9b07"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 10 : 10);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("b82be13943ab8ff905984dd9c506caf9d4d98cdaf174589040e016f564cdaf06",'hex');
            let hash = sha256.hex(headerhash).toString('hex');

            const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

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

            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            const txBlobStr = "013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000080ee3600000000000200000000000000e1247fa76cf3ea60f702267f4f45862ac168ee1eff95e006283125f392ab68cf0a0000000000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909070000006d61696e6e6574b82be13943ab8ff905984dd9c506caf9d4d98cdaf174589040e016f564cdaf0600000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f7572636522000000010202020202020202020202020202020202020202020202020202020202020202010d0c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000001000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290124c76ebd6ade72fbc7c638e901476f63566c49a7a97c47ab906d5c6f7fe9a19bd9fbebce567594ad712217c21cef778a2eebef94e1b203b21fc58a27ca1a9b07"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_expert_transfer`, model === "nanos" ? 18 : 18);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("b82be13943ab8ff905984dd9c506caf9d4d98cdaf174589040e016f564cdaf06",'hex');
            let hash = sha256.hex(headerhash).toString('hex');

            const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic delegation (%s)', async function (_, {model, prefix, path}) {
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

            const txBlobStr = "02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fa087c0377901000080ee3600000000000200000000000000a214f01a236e5793eef21efe8bdb0f9ec7b95f20d0d4c149e9fc8a58d21647c303000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e65741014d6a144218d679dd2509953f567ad2d0d6952713a9226fd3a6499a9d6167e00000000000100000006000000616d6f756e74050000000400ca9a3b080101010101010101010101010101010101010101010101010101010101010101010800000064656c6567617465030000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031606000000616d6f756e740100000000080300000002031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02611d93753628c649c117c1ed9672666aa63ed063ee44579da2e6ff58a8a82f6e24c3fce56b91097aba9e1600d8ee61064a3362ae3a0a32ccd3d6acba0339f0cc013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290150ea6e6a305a3ca68001ccecb8637bbbb6e4ffaae2fb52abcb86c09ec6e3044e23d3c7ff11b076ba6a69a46b9d7b53d435db3e3b872c8541b10b6ac5f790f208018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394015f3e4c89498e6f00cfe847b6cfe4ee96038aeb3b66f212afe548fe62a0820eaf3e9e0709fbf44a4f3686538ce40c418f474bdcdd707cb8c1829c71336f872506"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_delegation`, model === "nanos" ? 12 : 13);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("1014d6a144218d679dd2509953f567ad2d0d6952713a9226fd3a6499a9d6167e",'hex');
            let hash = sha256.hex(headerhash).toString('hex');

            const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });
});