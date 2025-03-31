/** ******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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
import Zemu from '@zondax/zemu'
import { defaultOptions, models, PATH } from "./common";
import CasperApp from "@zondax/ledger-casper";
// @ts-ignore
import * as secp256k1 from "secp256k1";

const sha256 = require("js-sha256");

const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";
const expected_address = "02028b2ddbe59976AD2f4138CA46553866De5124d13dB4e13611CA751EeddE9E0297";

jest.setTimeout(80000);

describe("SignMessage", function () {
  test.concurrent.each(models)("sign message", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      const respAddr = await app.getAddressAndPubKey(PATH);

      expect(respAddr.returnCode).toEqual(0x9000);
      expect(respAddr.errorMessage).toEqual("No errors");

      expect(respAddr.publicKey.toString("hex")).toEqual(expected_pk);

      const txBlobStr = "Casper Message:\nPlease sign this CSPR token donation";
      const txBlob = Buffer.from(txBlobStr, "utf8");
      const respRequest = app.signMessage(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_message`);

      let signatureResponse = await respRequest;

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      const msgHash = sha256.hex(txBlob).toString("hex");
      const pk = Uint8Array.from(Buffer.from(expected_pk, "hex"));
      expect(pk.byteLength).toEqual(33);
      const digest = Uint8Array.from(Buffer.from(msgHash, "hex"));
      const signature = Uint8Array.from(signatureResponse.signatureRSV);
      expect(signature.byteLength).toEqual(65);

      const signatureOk = secp256k1.ecdsaVerify(signature.slice(0, 64), digest, pk);
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign invalid message", async function (m) {
    const sim = new Zemu(m.path);
    try {
        await sim.start({ ...defaultOptions, model: m.name });
        const app = new CasperApp(sim.getTransport());

        const txBlobStr = "Sign message without prefix";
        const txBlob = Buffer.from(txBlobStr, "utf8");
        const respRequest = await app.signMessage(PATH, txBlob);

        expect(respRequest.returnCode).toEqual(0x6984);
        expect(respRequest.errorMessage).toEqual("Data is invalid : Unrecognized error code");
    } finally {
      await sim.close();
    }
  });
});
