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

import Zemu from "@zondax/zemu";
import { models, defaultOptions, PATH } from "./common";
import CasperApp from "@zondax/ledger-casper";
// @ts-ignore
import * as secp256k1 from "secp256k1";

const sha256 = require("js-sha256");

jest.setTimeout(180000);

describe("Generic", function () {
  test.concurrent.each(models)(
    "sign generic delegation with invalid entry point (%s)",
    async function (m) {
      const sim = new Zemu(m.path);
      try {
        await sim.start({ ...defaultOptions, model: m.name });
        const app = new CasperApp(sim.getTransport());

        // Enable expert mode
        await sim.toggleExpertMode();

        const expected_pk =
          "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";

        // #263 delegate_type__versioned_by_name_invalid_entrypoint_payment_system
        const txBlobStr =
          "0002031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fa087c0377901000080ee360000000000020000000000000039e6ee46a439892e9697c7ac4f242c732a02bcdfddea8f94918cd13c3469610c00000000070000006d61696e6e6574af1acd8fce2a8d40fa53fb8a71254dba9e268e91ac149b279ea5d64a7131b66700000000000100000006000000616d6f756e74050000000400ca9a3b080410000000696e76616c69645f636f6e7472616374010100000007000000696e76616c6964030000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031606000000616d6f756e74050000000400e1f5050803000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290191b1cfc40511075025f5cc7024ec1de623d8697837108696587676eb904603f484b991462a0978faa80fd281616e9db6e9af5077ea103315f1705e915a956b09018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394019e88a0ddd4d9c484807639b761ebe9ec8f925cebbcd78eb2548c2c785bb412663d0ad7d28d05c22d8be3ba3635f5db88a6a60d60c7588d192011d5ad128e940f02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02ac30a08f8d29c8995d7a6208eb79361d124720ba273257cd34638ca562af248a3831da2aa22041332870879901b5bbaa7633a0c72100864d9b1078bbd96741e0";

        const txBlob = Buffer.from(txBlobStr, "hex");
        const respRequest = app.sign(PATH, txBlob);

        // Wait until we are not in the main menu
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
        await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-delegation_invalid_entry_point`);

        let signatureResponse = await respRequest;

        expect(signatureResponse.returnCode).toEqual(0x9000);
        expect(signatureResponse.errorMessage).toEqual("No errors");

        let headerhash = Buffer.from(
          "af1acd8fce2a8d40fa53fb8a71254dba9e268e91ac149b279ea5d64a7131b667",
          "hex"
        );

        const hash = sha256.hex(headerhash).toString("hex");

        const pk = Uint8Array.from(Buffer.from(expected_pk, "hex"));
        expect(pk.byteLength).toEqual(33);
        const digest = Uint8Array.from(Buffer.from(hash, "hex"));
        const signature = Uint8Array.from(signatureResponse.signatureRSV);
        expect(signature.byteLength).toEqual(65);

        const signatureOk = secp256k1.ecdsaVerify(
          signature.slice(0, 64),
          digest,
          pk
        );

        expect(signatureOk).toEqual(true);
      } finally {
        await sim.close();
      }
    }
  );
});
