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

jest.setTimeout(100000);

beforeAll(async () => {
    await Zemu.checkAndPullImage()
})


describe('Generic', function () {
    test.each(models)('sign generic delegation with invalid entry point (%s)', async function ( m) {
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

            // #262 delegate-type:versioned-by-name_invalid:entrypoint_payment:system-missing:amount
            const txBlobStr = "011398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93caa087c0377901000060ea0000000000000200000000000000e483229a97b1318a4c7314a68197be3261b31526894a3455f1089c0fc7bb3a1a00000000070000006d61696e6e6574618de3fe29fe260e9fde8ff1e89c919238c8bf6f68f59f248b52770930a5370100000000000100000006000000706179696e67050000000400ca9a3b080410000000696e76616c69642d636f6e7472616374010100000007000000696e76616c6964030000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031606000000616d6f756e74050000000400e1f505080a000000011398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca01b99efa9087619436d6a37cd44255f902a90f3da1cdb3c829247dbb0ed759eec722fedc64127ae3f2cfaf562cdfded7ac4b154d91c866738492e1b49d48d59d0d020256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b292096702fdf9b44c8dca4d1b964b1abcc2cde5a0ff697283faa1879263bdbd93159ef33a0d233191e31d3317bee091643c5638cff2c4a40b824f539c666e164c20bcab5a02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0221144f796cf880c42b956a72b3d34825612840ae728d187d592f85ffec94247968ee318b19fc46738cdcd9c68497fe374bcbde3792132b7648ba561f8b089f22018a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f1701a7a5f9fb93862387e39625ed54a1ba05e59867a5485517dae8b52f623ddbfaf030053ed58d41b6e53ff7240ad6b7decffe4f476f58ffbb2e20ad6a643cb057020202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337024bc687803e6af6e9bbe91bfc0606decee6ed461a626a35267a55897087943a79157f961d42cb3f9f69f5d0f02c45a2adf392b217dc6e69864095b9d16721874a01ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c014645bba8924ab9cf2f813d94f15625eea0f31be3ee71e0a9d8b9691bf923b664289b8a2314131afb30687724c15a7acaa04a9e6e6b4afd4848d297870ceb8e06020362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f70236ac5428a14ba11b70b42eccd86b9412c5c5ab63fa3a81abce97f4c8b6e973ed34411e7d697ad169d1d878d80b0cab773b4c2805658013a89f64014aef7e87af0202989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f02bbe5d58b56a99ec7de882b2ccfc213437e56cf9fa19f2eb1d04535b69edab38f76e188d28a9e46b805330143d942c5ee35a1020cfd5539a2e974ed4dcbc7259d013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29011f1aaaf316e2ab06621370d2d6556fcf5ab3b2a0ea8ea9be08ccf7b3b76b7586a8b550df2a97968855df30faf4902d74a2a213d6ab33536e987313f9a2fa3509018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394019fe29fc2fc48fd7338624c876d4663b8d72ee486f35cdfbe57564ab70069b4f828fa955b02f6367583db8f5560ec063b2580a17c31f274052d400f816912c306"

            const txBlob = Buffer.from(txBlobStr, "hex");
            const respRequest = app.sign("m/44'/506'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-delegation_invalid_entry_point`)

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            let headerhash = Buffer.from("618de3fe29fe260e9fde8ff1e89c919238c8bf6f68f59f248b52770930a53701",'hex');
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

