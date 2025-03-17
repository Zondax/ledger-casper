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
import Zemu, { zondaxMainmenuNavigation, isTouchDevice, ButtonKind } from '@zondax/zemu'
import { defaultOptions, models, PATH } from "./common";
import CasperApp from "@zondax/ledger-casper";
// @ts-ignore
import * as secp256k1 from "secp256k1";

const sha256 = require("js-sha256");

const expected_pk = "028b2ddbe59976ad2f4138ca46553866de5124d13db4e13611ca751eedde9e0297";
const expected_address = "02028b2ddbe59976AD2f4138CA46553866De5124d13dB4e13611CA751EeddE9E0297";

jest.setTimeout(120000);

describe("Standard", function () {
  test.concurrent.each(models)("can start and stop container (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("main menu (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("get app version (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
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

  test.concurrent.each(models)("get address (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      const resp = await app.getAddressAndPubKey(PATH);
      console.log(resp);

      expect(resp.returnCode).toEqual(0x9000);
      expect(resp.errorMessage).toEqual("No errors");

      expect(resp.publicKey.toString("hex")).toEqual(expected_pk);
      expect(resp.Address).toEqual(expected_address);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("show address (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: isTouchDevice(m.name) ? 'Confirm' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new CasperApp(sim.getTransport());

      const respRequest = app.showAddressAndPubKey(PATH);

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-show_address`);

      const resp = await respRequest;
      console.log(resp);

      expect(resp.returnCode).toEqual(0x9000);
      expect(resp.errorMessage).toEqual("No errors");

      expect(resp.publicKey.toString("hex")).toEqual(expected_pk);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign basic normal (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      const respAddr = await app.getAddressAndPubKey(PATH);
      console.log(respAddr);

      expect(respAddr.returnCode).toEqual(0x9000);
      expect(respAddr.errorMessage).toEqual("No errors");

      expect(respAddr.publicKey.toString("hex")).toEqual(expected_pk);

      const txBlobStr =
        "00013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000080ee3600000000000200000000000000d271fba86310ea9bfe082283e77563edf5704fe544dfdf60ea70ac2f4cfb452f03000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e657408546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d26451000000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000000202020202020202020202020202020202020202020202020202020202020202020c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000003000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901dbacc351e84410cf86120cc93156d7cf9c74501b0ffedb1b7dedd5f07b5ca3b1e752be147d10cee92fbb41a67c65f3097b9ea7759339c455cb3508247d2a1a0f02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02421ee9300ceb7c0fe6d9c86e8c03cda468a967af670bcf8fb2624ce581c65c254e3c2caf3eb4e783db4d90105e80118c7b7116705387c39a9a3856ea38ae0f44018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401c8b75401757cf2d4989f70c1a775f5dd9b77f4adcdfad74f79f963610c84560ea57f5f6c660b719b8876a3ced58f2495fc70d9852ca3bc0c325c2cc46a2e9807";

      const txBlob = Buffer.from(txBlobStr, "hex");
      const respRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_basic_normal`);

      let signatureResponse = await respRequest;
      console.log(signatureResponse);

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      let headerhash = Buffer.from(
        "08546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d264510",
        "hex"
      );

      let hash = sha256.hex(headerhash).toString("hex");

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
  });

  test.concurrent.each(models)("sign expert transfer(%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      // Enable expert mode
      console.log("Set expert mode");
      await sim.toggleExpertMode();

      const txBlobStr =
        "00013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000080ee3600000000000200000000000000d271fba86310ea9bfe082283e77563edf5704fe544dfdf60ea70ac2f4cfb452f03000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202070000006d61696e6e657408546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d26451000000000000100000006000000616d6f756e74050000000400ca9a3b08050400000006000000616d6f756e74010000000008020000006964090000000100000000000000000d0506000000736f75726365210000000202020202020202020202020202020202020202020202020202020202020202020c0600000074617267657420000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f2000000003000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901dbacc351e84410cf86120cc93156d7cf9c74501b0ffedb1b7dedd5f07b5ca3b1e752be147d10cee92fbb41a67c65f3097b9ea7759339c455cb3508247d2a1a0f02031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02421ee9300ceb7c0fe6d9c86e8c03cda468a967af670bcf8fb2624ce581c65c254e3c2caf3eb4e783db4d90105e80118c7b7116705387c39a9a3856ea38ae0f44018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401c8b75401757cf2d4989f70c1a775f5dd9b77f4adcdfad74f79f963610c84560ea57f5f6c660b719b8876a3ced58f2495fc70d9852ca3bc0c325c2cc46a2e9807";

      const txBlob = Buffer.from(txBlobStr, "hex");
      const respRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_expert_transfer`);

      let signatureResponse = await respRequest;
      console.log(signatureResponse);

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      let headerhash = Buffer.from(
        "08546b91f63d6435f071bcb0d35779f8717378b84762b8b418d1fa3b7d264510",
        "hex"
      );
      let hash = sha256.hex(headerhash).toString("hex");

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
  });

  test.concurrent.each(models)("sign basic delegation (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      const respAddr = await app.getAddressAndPubKey(PATH);
      console.log(respAddr);

      expect(respAddr.returnCode).toEqual(0x9000);
      expect(respAddr.errorMessage).toEqual("No errors");

      expect(respAddr.publicKey.toString("hex")).toEqual(expected_pk);

      const txBlobStr =
        "00013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c0377901000060ea0000000000000200000000000000a214f01a236e5793eef21efe8bdb0f9ec7b95f20d0d4c149e9fc8a58d21647c30a0000000000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909070000006d61696e6e65749b100331533e4ae46966e83243bcac343712934d92c5e8f0218c39fa5d14a70800000000000100000006000000616d6f756e74050000000400ca9a3b080101010101010101010101010101010101010101010101010101010101010101010800000064656c6567617465030000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031606000000616d6f756e7401000000000801000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901eda769d0ce6ec8d0841b401fb3d6c52f5903eb4572790ec2b8cac19a85004cdd38e20b9ea3bd16ef1cfe5b8f87a4631f530e714078eacc57eb8e21266b073b0c";

      const txBlob = Buffer.from(txBlobStr, "hex");
      const respRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_basic_delegation`);

      let signatureResponse = await respRequest;
      console.log(signatureResponse);

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      let headerhash = Buffer.from(
        "9b100331533e4ae46966e83243bcac343712934d92c5e8f0218c39fa5d14a708",
        "hex"
      );
      let hash = sha256.hex(headerhash).toString("hex");
      console.log("hash", hash); // 968b5805da8869e92f5b497cffa37a461299a68d31701d7be09201619e2aa830
      //but 00005805da8869e92f5b497cffa37a461299a68d31701d7be09201619e2aa830

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
  });

  test.concurrent.each(models)("sign generic native transfer(%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      // Enable expert mode
      console.log("Set expert mode");
      await sim.toggleExpertMode();

      // #209 native_transfer__target__ed25519_public_key__source__none_payment_system
      const txBlobStr = "0002031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fa087c03779010000005c26050000000002000000000000000715584c9cb52e0c00f34aa6b36bd5cc9882af246c24771e3f6c32520bdec52600000000070000006d61696e6e6574b5d8be1f6adce61989ac678515215c9d59dbcba9b1635c9ed1eec976382e996500000000000100000006000000616d6f756e74050000000400ca9a3b08050300000006000000616d6f756e744100000040ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff080200000069640900000001ffffffffffffffff0d050600000074617267657421000000012bac1d0ff9240ff0b7b06d555815640497861619ca12583ddef434885416e69b1603000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901437a29fae90f8e586055e6f955d8583c4c533f596a197541513d46ee48754f9d5dac6217876672015d28225eea87ae6106818e4ede507348d77a10393323cc08018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394016fc1a3f7314f5d27195aee8bfe04ecfb10dff9ae9ada1521e3d358ceb6ca76339529ad3a3c68d98f8cd974d27fd9e69ac1b912637c639c14a2c37797e2a2750202031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02ef9227c5ff2b6142d073c03efff91bd313dd3e1c9abeb9badcad519eac40c285685e6534fa2783db97d7f6ce0f10cdea5692edc9e6e348b1dc8a71dc676e8bd9";

      const txBlob = Buffer.from(txBlobStr, "hex");
      const respRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-generic_native_transfer`);

      let signatureResponse = await respRequest;
      console.log(signatureResponse);

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      let headerhash = Buffer.from(
        "b5d8be1f6adce61989ac678515215c9d59dbcba9b1635c9ed1eec976382e9965",
        "hex"
      );

      let hash = sha256.hex(headerhash).toString("hex");

      const pk = Uint8Array.from(Buffer.from(expected_pk, "hex"));
      expect(pk.byteLength).toEqual(33);
      const digest = Uint8Array.from(Buffer.from(hash, "hex"));

      // use the legacy field that does not include the V component
      const signature = Uint8Array.from(signatureResponse.signatureRS);
      expect(signature.byteLength).toEqual(64);

      const signatureOk = secp256k1.ecdsaVerify(
        signature,
        digest,
        pk
      );
      expect(signatureOk).toEqual(true);
    } finally {
      await sim.close();
    }
  });

  test.concurrent.each(models)("sign generic delegation (%s)", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      // Enable expert mode
      console.log("Set expert mode");
      await sim.toggleExpertMode();

      // #249  delegate_type__by_hash_missing_amount_payment_system`
      const txBlobStr =
        "00013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29a087c03779010000005c2605000000000200000000000000c477ca557dcab12d8bd0c1a6267ed878a28e928a95585950f3585eed22ed5cfb00000000070000006d61696e6e657499619ed851e18d3c4d4f35c179f17c35c28998f74caac8fe4304f9ec52bf368d00000000000100000006000000616d6f756e74050000000400ca9a3b080101010101010101010101010101010101010101010101010101010101010101010800000064656c6567617465020000000900000064656c656761746f7221000000010101010101010101010101010101010101010101010101010101010101010101160900000076616c696461746f72210000000103030303030303030303030303030303030303030303030303030303030303031601000000013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da2901915fd384d117294602e6c7669fe391fdcf923ef732d8173d98e16426faa37f74c42078a53aa585a37227f48197d54e437fcc7035432f3c91d3eb976c70433d0e";

      const txBlob = Buffer.from(txBlobStr, "hex");
      const respRequest = app.sign(PATH, txBlob);

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-generic_delegation`);

      let signatureResponse = await respRequest;
      console.log(signatureResponse);

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      let headerhash = Buffer.from(
        "99619ed851e18d3c4d4f35c179f17c35c28998f74caac8fe4304f9ec52bf368d",
        "hex"
      );

      let hash = sha256.hex(headerhash).toString("hex");

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
  });


  test.concurrent.each(models)("sign wasm deploy", async function (m) {
    const sim = new Zemu(m.path);
    try {
      await sim.start({ ...defaultOptions, model: m.name });
      const app = new CasperApp(sim.getTransport());

      const respAddr = await app.getAddressAndPubKey(PATH);
      console.log(respAddr);

      expect(respAddr.returnCode).toEqual(0x9000);
      expect(respAddr.errorMessage).toEqual("No errors");

      expect(respAddr.publicKey.toString("hex")).toEqual(expected_pk);

      const txBlobStr =
        "01ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7ca087c0377901000080ee360000000000020000000000000077acc4d0e0b59fd05c8b0210d10722c6d00381f8059cb2a8c1a513e8acd004550a0000000000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909070000006d61696e6e6574ca815f7a03a7066e117cf30b9b141b2d73e5a7f2448c43d0466126b8e8a2355e00000000000100000006000000616d6f756e74050000000400ca9a3b0800000000002800000003000000553634080000000000000000000000050300000055333204000000ffffffff040400000055526566210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75010c020000005538010000000b03030000004b6579210000000401010101010101010101010101010101010101010101010101010101010101010b030000004b6579210000000701010101010101010101010101010101010101010101010101010101010101010b03000000493634080000000000000000000080020a0000004f7074696f6e285538290200000001640d030400000055526566210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75020c030000005533320400000000000000041a0000005475706c6533285b55382c20426f6f6c2c20537472696e675d290c0000000001060000007475706c65331403000a030000004b6579210000000c01010101010101010101010101010101010101010101010101010101010101010b04000000553132381100000010ffffffffffffffffffffffffffffffff06030000004b6579210000000601010101010101010101010101010101010101010101010101010101010101010b0400000055526566210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75000c0e0000006c6973742d7075626c69636b657904000000000000000e16030000004b6579210000000001010101010101010101010101010101010101010101010101010101010101010b1d000000526573756c74207b206f6b3a20426f6f6c2c206572723a20493332207d0200000001001000010300000049333204000000ffffff7f0104000000553235362100000020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07030000004b657922000000020101010101010101010101010101010101010101010101010101010101010101070b0a0000004f7074696f6e2855382901000000000d030400000055526566210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75070c0900000062797465617272617904000000000000000e03110000005475706c6532285b55382c205536345d29090000000b570400000000000013030506000000537472696e67110000000d00000073616d706c652d737472696e670a03000000493634080000000000000000000000020300000049363408000000ffffffffffffff7f02030000004b6579210000000301010101010101010101010101010101010101010101010101010101010101010b0400000055526566210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75040c09000000627974656172726179240000002000000001010101010101010101010101010101010101010101010101010101010101010e03030000004b6579210000000a00000000000000000000000000000000000000000000000000000000000000000b090000005075626c69634b65790100000000160300000055363408000000ffffffffffffffff050400000055526566210000004acfcf6c684c58caf6b3296e3a97c4a04afaf77bb875ca9a40a45db254e94a75050c030000004b6579210000000801010101010101010101010101010101010101010101010101010101010101010b0400000055323536010000000007030000004b6579090000000500000000000000000b04000000426f6f6c01000000000002000000553801000000ff030a000000011398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca014c38e7abda8af0b36035ff33b281db799f1986343b217fe76afb116a0bd5a90f0983d875d49b32eedf7608dbea42189f8a360deb4a6622a81b51e052a6896301013b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290176b2189432e2b42be4f9a757b8d5a65dced3fdab364c3aaddb8b68ca87125f0df148b6e1909db5f0c68527ced040c21711bcaccf206177bd57d5ec8d23e8cd01018139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39401ccd95d3b27e49ef6dcbd28e6017069954df1fea1a7389eb38f4d2e30aeac649e0339cb173376ae26a4b579059f89c029e56e95a90cceaa475096e9f9ef3dfd0b018a875fff1eb38451577acd5afee405456568dd7c89e090863a0557bc7af49f170166b19f855c6ba395727dfd822274d2a3707a7602daf341c9ad8e8222b298247f57f0715393f938d34f8bbdb5a57ab28efcbd19313540b41e4b43e35d953dbd0501ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c019763175645b99d559ab84dc7f46adfbbc5bdf3a59e0e006d286d2563d3683026acdd9cfe3779f71be271b4da4eb1364b253004f15a10d2774734a185a49da70f0202531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33702dffb7ae96b938c21b3b88d656d6a1396105a6f718e85b5a26a66327151fe6a1c3861744ee3817ff10073478ab506b4391f84ba044d34c0f2a0b098fae9d13d92020256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967026b921736e6acb062ad798173be50cc4637b31a399091002b20df6237de8b30ca42e5a2d0e920016b8468473130ec3b54b01da49cc024ef5536df7263c4f4b3770202989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f02123e6aa43180b84cb53e215ff8aa3f54c1c58424d22cbef4b5b7578391bde1bb4827eb92bfc9555cba43c700ef769633928150c5af07772848e4f356ce07170202031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02b50fc36b8fe516c5cb7d6178b656cd4b4f7436a4f56c23e0af62d89be930e0d256ed930fd826a1c28fcb8d83c432d5c095e861589da593c88574b76e5e91ceec020362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f702749c6bd64ed493e20476e713383555fe3faffe300d5c783611321620a1dfb38d2abb0dd0834fdc40258c6f4afaf9c352db0b4570eeeb9faaed592c3adee3b3f4";

      const txBlob = Buffer.from(txBlobStr, "hex");
      const respRequest = app.signWasmDeploy(PATH, txBlob);

      // Wait until we send everything to device
      const waitText = m.name == 'stax' || m.name == 'flex' ? "Review" : (m.name == 'nanos') ? "DeployHash" : "Please";
      await sim.waitForText(waitText, 30000);
      await sim.compareSnapshotsAndApprove(".", `${m.prefix.toLowerCase()}-sign_raw_wasm`)

      let signatureResponse = await respRequest;
      console.log(signatureResponse);

      expect(signatureResponse.returnCode).toEqual(0x9000);
      expect(signatureResponse.errorMessage).toEqual("No errors");

      let headerhash = Buffer.from(
        "cA815f7a03A7066E117Cf30B9b141b2d73e5a7f2448c43d0466126B8E8A2355E",
        "hex"
      );

      let hash = sha256.hex(headerhash).toString("hex");

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
  });

});
