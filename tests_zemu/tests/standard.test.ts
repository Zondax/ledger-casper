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

import { APP_SEED, models } from './common'
import Zemu, { DEFAULT_START_OPTIONS } from '@zondax/zemu'
import CasperApp from "@zondax/ledger-casper";
// @ts-ignore
import * as secp256k1 from "secp256k1";

const sha256 = require('js-sha256');

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(90000);

beforeAll(async () => {
    await Zemu.checkAndPullImage()
})

describe('Standard', function () {
    test.each(models)('can start and stop container (%s)', async function (m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
        } finally {
            await sim.close();
        }
    });

    test.each(models)('main menu (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
            await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, [1, 0, 0, 4, -5])
        } finally {
            await sim.close();
        }
    });

    test.each(models)('get app version (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
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

    test.each(models)('get address (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
            const app = new CasperApp(sim.getTransport());

            const resp = await app.getAddressAndPubKey("m/44'/506'/0'/0/0");

            console.log(resp)

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";
            const expected_address = "02028b2ddbe59976AD2f4138CA46553866De5124d13dB4e13611CA751EeddE9E0297";

            expect(resp.publicKey.toString('hex')).toEqual(expected_pk);
            expect(resp.address).toEqual(expected_address);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('show address (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
            const app = new CasperApp(sim.getTransport());

            const respRequest = app.showAddressAndPubKey("m/44'/506'/0'/0/0");

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-show_address`)

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

    test.each(models)('sign basic normal (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
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

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_basic_normal`)

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("08546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d264510",'hex');

            let hash = sha256.hex(headerhash).toString('hex');

            const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRSV);
            expect(signature.byteLength).toEqual(65);

            const signatureOk = secp256k1.ecdsaVerify(signature.slice(0, 64), digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });


    test.each(models)('sign expert transfer(%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
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

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_expert_transfer`)

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("08546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d264510",'hex');
            let hash = sha256.hex(headerhash).toString('hex');

            const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRSV);
            expect(signature.byteLength).toEqual(65);

            const signatureOk = secp256k1.ecdsaVerify(signature.slice(0, 64), digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic delegation (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
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

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_basic_delegation`)

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("9b100331533e4ae46966e83243bcac343712934d92c5e8f0218c39fa5d14a708",'hex');
            let hash = sha256.hex(headerhash).toString('hex');
            console.log("hash", hash)// 968b5805da8869e92f5b497cffa37a461299a68d31701d7be09201619e2aa830
            //but 00005805da8869e92f5b497cffa37a461299a68d31701d7be09201619e2aa830

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

    test.each(models)('sign generic native transfer(%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
            const app = new CasperApp(sim.getTransport());

            // Enable expert mode
            console.log("Set expert mode")
            await sim.clickRight();
            await sim.clickBoth();
            await sim.clickLeft();


            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            // #240 native_transfer-missing:amount_payment:system-missing:amount
            const txBlobStr = "01ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7ca087c03779010000005c26050000000002000000000000006f43ab89f962d9bbdcd8a1a1a5429deb24da8476679087953d9f95a3942178c603000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e6574c2baafd298bde51d15edb71b54d2b2ae695f55a4f164e063fc1d28ad5134d0d100000000000100000006000000706179696e67050000000400ca9a3b0805020000000200000069640800000001000000000000000506000000746172676574210000000101010101010101010101010101010101010101010101010101010101010101010c0a00000001ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c01c914688d05b837b14736eb70deab3c5a9ba4715a0a2163b431ee3e2d1c443418298cbac10a29cb24244b48290a3fddc06cb57effac126b0e902fd33e8885c009018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394010d9eb25b1a8b5817045400990f39603b3a77eacc5e411c6bec8539892a46833c10e5971def3411ebc8a2772d3d8dd1bddf612aeb8ad8cf08c25138d6fb3719090202989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f021b4ab5df16a630fb39126340fa3db87846029bf420f74db18365a211499fac6a0558fc4ee6c9d74317901b54d33cd40bb933a117c62614c6d4be46406131e6d0018a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f17017c48e268b22c7e5043fc47f52ba17c0aa4a8f12a229fca2ebc509ab8d095969ad9ea28910efccce55fa85be6555399782a456945899f46d1d36268a6d4e55d0d020256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b292096702bd71d0d55862a2908fedff2953a59deb2e912c9e711301423d3ee25ba068931b6f1202b024456c8491185553d5124ea57cd312306d05b2202e92e9a33306c775013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29011d2a8ccf86828493391952f0ff9542a1bd615a50d4449aa5f38c198775bc7450c61274da1036a7d10ae17c0b7268103c74e2e8afb179599ea85c3a1ca62869000202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337022f92f8d3c489cecbad51b91d18c8df14444623a6e387f98ecfe0c144bbf14a934bbefc3dcd55680bd1b11dd8d15519f578ac3e3599ece831a6f821cd584e348702031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0261b88acc3e26b47e692f8c932de50a153c83c2aadebdf6a4a2637214f43121bb0691c4c3d569ec06bf2f1a5059fe796bf4803ac03804e936e4407cb42ae02dde011398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca0112196a08e7e4084eea488f4af49b4eb4fe5ac9db1ab7a19dbcf943fcb760099f4ec8af7c1753a3e3d6041d583b2c4434ea25e3daa8789fd5252db8353ef76904020362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f702c1c7425a8664e367ff8c5f57b0828ec521fdf6410579798b52e01a113e576a6b71a9c786cec45835edaccd3d437bee4efdc3b73508f99e32fb6989f7e72f3e72"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-generic_native_transfer`)

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("c2baafd298bde51d15edb71b54d2b2ae695f55a4f164e063fc1d28ad5134d0d1",'hex');
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

    test.each(models)('sign generic delegation (%s)', async function ( m) {
        const sim = new Zemu(m.path);
        try {
            await sim.start({ ...defaultOptions, model: m.name })
            const app = new CasperApp(sim.getTransport());

            // Enable expert mode
            console.log("Set expert mode")
            await sim.clickRight();
            await sim.clickBoth();
            await sim.clickLeft();


            const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

            // #248  delegate-type:by-hash_missing:amount_payment:system-missing:amount`
            const txBlobStr = "018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394a087c0377901000080ee3600000000000200000000000000470d89c68dbb472faefbeb4bfb5ec23be9ca62d1834ac238b74e869e2837338600000000070000006d61696e6e65743bcacd42c232c3be6fd4463b1268be89a1cd5ee40a41502119c9d80e579cd30700000000000100000006000000706179696e67050000000400ca9a3b080101010101010101010101010101010101010101010101010101010101010101010800000064656c6567617465020000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031603000000018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401427f04259e7a61153c3f7cf66268f2c13afc42f6a35de46f7d7738f72f09bca6e49d53912f21da8a443370e9e258db678dee5ed9b1a06640fee972618a064f0102031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02f86e632f25cccabd3ec47c76d8484a1970ee1e359fb873c872cc3d573f331c470a8dd15ba159e05d1d239af72758051234ab2c59cf3a74de0f8f89506b4ca9c4013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29014d5ef196b38604c66b3fe1ee37e652f40e1f5eef9f4ceaa85ae90d2427d191789ff80a1f7a587df125b5816af26dc02e6a68da47494cc21c293f91b3bda8f708"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-generic_delegation`)

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("3bcacd42c232c3be6fd4463b1268be89a1cd5ee40a41502119c9d80e579cd307",'hex');
            let hash = sha256.hex(headerhash).toString('hex');

            const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
            expect(pk.byteLength).toEqual(33);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRSV);
            expect(signature.byteLength).toEqual(65);

            const signatureOk = secp256k1.ecdsaVerify(signature.slice(0, 64), digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });
});

