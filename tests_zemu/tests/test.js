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

            const txBlobStr = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee36000000000001000000000000004811966d37fe5674a8af4001884ea0d9042d1c06668da0c963769c3a01ebd08f0100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c657725c391ccf5053bbe48b6a99843ceef4b342e72cc1daf195d1bcfa8d805f0d8020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 14 : 15);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let hash = txBlob.slice(144,176);

            const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString('hex'), 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash.toString('hex'), 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });
});

describe('Deploytypes', function () {
    test.each(models)('sign basic normal -- Case0(%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const device_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            const txBlobStr = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b00000000000200000000000000f2e0782bba4a0a9663cafc7d707fd4a74421bc5bfef4e368b7e8f38dfab87db8020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e6574d7a68bbe656a883d04bba9f26aa340dbe3f8ec99b2adb63b628f2bc92043199800000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e740600000005005550b40508060000007461726765742000000001010101010101010101010101010101010101010101010101010101010101010f200000000200000069640900000001e7030000000000000d050f0000006164646974696f6e616c5f696e666f140000001000000074686973206973207472616e736665720a01000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce55370195a68b1a05731b7014e580b4c67a506e0339a7fffeaded9f24eb2e7f78b96bdd900b9be8ca33e4552a9a619dc4fc5e4e3a9f74a4b0537c14a5a8007d62a5dc06"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_case0`, model === "nanos" ? 16 : 17);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal -- Case1(%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const txBlobStr = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000009bdb14ca4d83ff840565406ccad54176ee690a7cbdb1423d765dc9905c759364020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65748378f11139a6d65575cf839691fce97bc37c4f6c5d65e0be12b3d41a0815344700000000000100000006000000616d6f756e74050000000400ca9a3b080103030303030303030303030303030303030303030303030303030303030303030e000000706c656173655f63616c6c5f6d650900000008000000626f6f6c5f617267010000000100070000006933325f61726704000000ffffffff01070000006936345f61726708000000feffffffffffffff020600000075385f617267010000000403070000007533325f617267040000000500000004070000007536345f61726704000000060000000408000000753132385f6172670200000001070608000000753235365f6172670200000001080608000000753531325f6172670200000001090601000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce553701ef2d191d0635e05b1ed704f286e5d0de626e744180289493c6742ba768034e8edca20c95126876541812a9d941237d891cb6cb72ce11284829c1e0af8afa0506"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_case1`, model === "nanos" ? 31 : 30);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal -- Case2(%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const txBlobStr = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b00000000000200000000000000855973990b9fc55432f1d889a96efb688df506b659a1e78d2641868e84e97176020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65747f1353d9a0ec2b4113a789dc61598a36845b4aec40c51f79105c2e432b91c22700000000000100000006000000616d6f756e74050000000400ca9a3b080216000000646563656e7472616c697a65645f65786368616e676508000000747261736e666572060000000a0000006172675f737472696e670a00000006000000616c6c5f696e0a0e0000006172675f7075626c69635f6b6579210000000166be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a160f0000006172675f6f7074696f6e5f6e6f6e6501000000000d0a100000006172675f6f7074696f6e5f666972737405000000010a0000000d04110000006172675f6f7074696f6e5f7365636f6e642100000001147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0d0f20000000100000006172675f6163636f756e745f6861736820000000147f2cc33b4fdb04ab4e9ef2c067137177097ba50a544a0a343ce636028fcfcf0f2000000001000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce55370186660813374d3a8092a116ff0db0600a193517dbc0b2b1ca0b892ba16d44731cdb37caa7c7109686ba5827d89d791bf1ba21a95463fb484a800d2601ddbf6900"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_case2`, model === "nanos" ? 31 : 30);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal -- Case3(%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new CasperApp(sim.getTransport());

            const txBlobStr = "017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537a087c0377901000040771b000000000002000000000000009bd53cb2ae84eb661cfdd32008e34edc3abd0a3aa054f7aea910690fd973b860020000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f1010101010101010101010101010101010101010101010101010101010101010070000006d61696e6e65742f043befbe920560fe3987f2bf4ad73bdaa73213d7bea55c799ca0446c3eca4c00000000000100000006000000616d6f756e74050000000400ca9a3b08030303030303030303030303030303030303030303030303030303030303030303010c0000000b000000766573745f746f6b656e73080000000d0000006172675f726573756c745f6f6b05000000017b00000010040a0e0000006172675f726573756c745f65727211000000000c000000686172642070726f626c656d10040a070000006172675f6d617064000000020000000b0000006163636f756e745f6f6e650166be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a0b0000006163636f756e745f74776f010b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d110a160d0000006172675f656d7074795f6d617004000000000000001104020a0000006172675f7475706c6531040000000a00000012040a0000006172675f7475706c65320e0000000b000000060000007365636f6e6413040a0a0000006172675f7475706c6533100000000c000000060000007365636f6e641e0114040a130300080000006172675f756e6974000000000901000000017f747b67bd3fe63c2a736739dfe40156d622347346e70f68f51c178a75ce5537011557487c1fd82c5cc91e7170c94025c1438ef88670494b418f7b2f29dfb115447b7a4e91453d10f31ef94e7fa2f401153f2968dc7a045178d9557321de6a5404"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_case3`, model === "nanos" ? 31 : 30);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal -- Modulebytes(%s)', async function (_, {model, prefix, path}) {
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

            const txBlobStr = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee360000000000010000000000000046e03db2b69b1b2d917711991fab1d7fae72dac74eea1fa18d04d4f9a7024c850100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c650da67c5122086325bafdf7fa15a342971c0ae2fa8e15a330178b3b460a68cd1a0021000000ababababababababababababababababababababababababababababababababab01000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_modulebytes`, model === "nanos" ? 14 : 15);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let hash = txBlob.slice(144,176);

            const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString('hex'), 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash.toString('hex'), 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal -- StoredContractByHash(%s)', async function (_, {model, prefix, path}) {
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

            const txBlobStr = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee36000000000001000000000000005ecf9b7c916e59d106dc0f205fe8ade59c26bd321c5e90b44c970fd30402a2930100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c655dd440a64c305581ecf8f4dfaee0ed538817a0bdf2857a4ed6a6f4530ef14488010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_storedcontractbyhash`, model === "nanos" ? 15 : 16);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let hash = txBlob.slice(144,176);

            const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString('hex'), 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash.toString('hex'), 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal -- StoredVersionedContractByHash(%s)', async function (_, {model, prefix, path}) {
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

            const txBlobStr = "02030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d1774cbaf9747501000080ee3600000000000100000000000000e159c9ed050bdc2600b070d7a29e436ee53e62896ef830473cf1a669bc8b16440100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c65141722ad47b6c586e2e03825e4e0e2190f107321e9cca3d8bd692b5f8f11a984020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001030f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0190340000070000006578616d706c650100000006000000616d6f756e7404000000e8030000010100000002030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_storedversionedcontractbyhash`, model === "nanos" ? 18 : 19);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let hash = txBlob.slice(144,176);

            const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString('hex'), 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash.toString('hex'), 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });
});