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

const sha256 = require('js-sha256');

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve("../app/output/app_s.elf");
const APP_PATH_X = Resolve("../app/output/app_x.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"

var simOptions = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`,
    X11: false,
    startText: 'Ready'
};

let models = [
    ['S', {model: 'nanos', prefix: 'S', path: APP_PATH_S}],
    ['X', {model: 'nanox', prefix: 'X', path: APP_PATH_X}]
]

jest.setTimeout(60000);

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
            await sim.navigateAndCompareSnapshots(".", `${prefix.toLowerCase()}-mainmenu`, [5]);
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

            const txBlobStr = "013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000080ee3600000000000200000000000000d271fba86310ea9bfe082283e77563edf5704fe544dfdf60ea70ac2f4cfb452f03000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e657408546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d26451000000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000000202020202020202020202020202020202020202020202020202020202020202020c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000003000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901dbacc351e84410cf86120cc93156d7cf9c74501b0ffedb1b7dedd5f07b5ca3b1e752be147d10cee92fbb41a67c65f3097b9ea7759339c455cb3508247d2a1a0f02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02421ee9300ceb7c0fe6d9c86e8c03cda468a967af670bcf8fb2624ce581c65c254e3c2caf3eb4e783db4d90105e80118c7b7116705387c39a9a3856ea38ae0f44018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401c8b75401757cf2d4989f70c1a775f5dd9b77f4adcdfad74f79f963610c84560ea57f5f6c660b719b8876a3ced58f2495fc70d9852ca3bc0c325c2cc46a2e9807"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 10 : 11);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("08546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d264510",'hex');

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

            const txBlobStr = "013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000080ee3600000000000200000000000000d271fba86310ea9bfe082283e77563edf5704fe544dfdf60ea70ac2f4cfb452f03000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e657408546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d26451000000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000000202020202020202020202020202020202020202020202020202020202020202020c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000003000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901dbacc351e84410cf86120cc93156d7cf9c74501b0ffedb1b7dedd5f07b5ca3b1e752be147d10cee92fbb41a67c65f3097b9ea7759339c455cb3508247d2a1a0f02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02421ee9300ceb7c0fe6d9c86e8c03cda468a967af670bcf8fb2624ce581c65c254e3c2caf3eb4e783db4d90105e80118c7b7116705387c39a9a3856ea38ae0f44018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401c8b75401757cf2d4989f70c1a775f5dd9b77f4adcdfad74f79f963610c84560ea57f5f6c660b719b8876a3ced58f2495fc70d9852ca3bc0c325c2cc46a2e9807"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_expert_transfer`, model === "nanos" ? 18 : 19);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("08546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d264510",'hex');
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

            const txBlobStr = "013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000060ea0000000000000200000000000000a214f01a236e5793eef21efe8bdb0f9ec7b95f20d0d4c149e9fc8a58d21647c30a0000000000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909070000006d61696e6e65749b100331533e4ae46966e83243bcac343712934d92c5e8f0218c39fa5d14a70800000000000100000006000000616d6f756e74050000000400ca9a3b080101010101010101010101010101010101010101010101010101010101010101010800000064656c6567617465030000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031606000000616d6f756e7401000000000801000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901eda769d0ce6ec8d0841b401fb3d6c52f5903eb4572790ec2b8cac19a85004cdd38e20b9ea3bd16ef1cfe5b8f87a4631f530e714078eacc57eb8e21266b073b0c"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_delegation`, model === "nanos" ? 12 : 13);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("9b100331533e4ae46966e83243bcac343712934d92c5e8f0218c39fa5d14a708",'hex');
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

