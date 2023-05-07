/** ******************************************************************************
 *  (c) 2021-2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
	@@ -13,8 +13,7 @@
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
import { DEFAULT_START_OPTIONS, IDeviceModel } from '@zondax/zemu'

const Resolve = require("path").resolve;

export const APP_SEED =
  "equip will roof matter pink blind book anxiety banner elbow sun young";

const APP_PATH_S = Resolve("../app/output/app_s.elf");
const APP_PATH_X = Resolve("../app/output/app_x.elf");
const APP_PATH_SP = Resolve("../app/output/app_s2.elf");
const APP_PATH_ST = Resolve("../app/output/app_stax.elf");

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

export const PATH = "m/44'/506'/0'/0/0"

export const models: IDeviceModel[] = [
  { name: "nanos", prefix: "S", path: APP_PATH_S },
  { name: "nanox", prefix: "X", path: APP_PATH_X },
  { name: "nanosp", prefix: "SP", path: APP_PATH_SP },
  { name: "stax", prefix: "ST", path: APP_PATH_ST },
];
