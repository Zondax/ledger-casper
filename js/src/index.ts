/** ******************************************************************************
 *  (c) 2019-2020 Zondax GmbH
 *  (c) 2016-2017 Ledger
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
import Transport from '@ledgerhq/hw-transport';
import {ResponseAddress, ResponseAppInfo, ResponseSign, ResponseVersion} from './types';
import {
    CHUNK_SIZE,
    CLA,
    errorCodeToString,
    getVersion,
    INS,
    LedgerError,
    P1_VALUES,
    PAYLOAD_TYPE,
    PKLEN,
    ADDRESS_LEN,
    processErrorResponse,
    serializePath, SIGLEN_RS, SIGLEN_RSV,
} from './common';

export {LedgerError};
export * from './types';

function processGetAddrResponse(response: Buffer) {
    let partialResponse = response;

    const errorCodeData = partialResponse.slice(-2);
    const returnCode = (errorCodeData[0] * 256 + errorCodeData[1]);

    const publicKey = Buffer.from(partialResponse.slice(0, PKLEN));

    partialResponse = partialResponse.slice(PKLEN);

    const Address = Buffer.from(partialResponse.slice(0, -2)).toString();

    return {
        publicKey,
        Address,
        returnCode,
        errorMessage: errorCodeToString(returnCode),
    };
}

export default class CasperApp {
    private transport: Transport;

    constructor(transport: Transport) {
        if (!transport) {
            throw new Error('Transport has not been defined');
        }
        this.transport = transport
    }

    static prepareChunks(serializedPathBuffer: Buffer, message: Buffer) {
        const chunks = [];

        // First chunk (only path)
        chunks.push(serializedPathBuffer);

        const messageBuffer = Buffer.from(message);

        const buffer = Buffer.concat([messageBuffer]);
        for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
            let end = i + CHUNK_SIZE;
            if (i > buffer.length) {
                end = buffer.length;
            }
            chunks.push(buffer.slice(i, end));
        }

        return chunks;
    }

    async signGetChunks(path: string, message: Buffer) {
        return CasperApp.prepareChunks(serializePath(path), message);
    }

    async getVersion(): Promise<ResponseVersion> {
        return getVersion(this.transport).catch(err => processErrorResponse(err));
    }

    async getAppInfo(): Promise<ResponseAppInfo> {
        return this.transport.send(0xb0, 0x01, 0, 0).then(response => {
            const errorCodeData = response.slice(-2);
            const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

            const result: { errorMessage?: string; returnCode?: LedgerError } = {};

            let appName = 'err';
            let appVersion = 'err';
            let flagLen = 0;
            let flagsValue = 0;

            if (response[0] !== 1) {
                // Ledger responds with format ID 1. There is no spec for any format != 1
                result.errorMessage = 'response format ID not recognized';
                result.returnCode = LedgerError.DeviceIsBusy;
            } else {
                const appNameLen = response[1];
                appName = response.slice(2, 2 + appNameLen).toString('ascii');
                let idx = 2 + appNameLen;
                const appVersionLen = response[idx];
                idx += 1;
                appVersion = response.slice(idx, idx + appVersionLen).toString('ascii');
                idx += appVersionLen;
                const appFlagsLen = response[idx];
                idx += 1;
                flagLen = appFlagsLen;
                flagsValue = response[idx];
            }

            return {
                returnCode,
                errorMessage: errorCodeToString(returnCode),
                //
                appName,
                appVersion,
                flagLen,
                flagsValue,
                flagRecovery: (flagsValue & 1) !== 0,
                // eslint-disable-next-line no-bitwise
                flagSignedMcuCode: (flagsValue & 2) !== 0,
                // eslint-disable-next-line no-bitwise
                flagOnboarded: (flagsValue & 4) !== 0,
                // eslint-disable-next-line no-bitwise
                flagPINValidated: (flagsValue & 128) !== 0,
            };
        }, processErrorResponse);
    }

    async getAddressAndPubKey(path: string): Promise<ResponseAddress> {
        const serializedPath = serializePath(path);
        return this.transport
            .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [0x9000])
            .then(processGetAddrResponse, processErrorResponse);
    }

    async showAddressAndPubKey(path: string): Promise<ResponseAddress> {
        const serializedPath = serializePath(path);

        return this.transport
            .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [
                LedgerError.NoErrors,
            ])
            .then(processGetAddrResponse, processErrorResponse);
    }

    async signSendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, instruction: number): Promise<ResponseSign> {
        let payloadType = PAYLOAD_TYPE.ADD;
        if (chunkIdx === 1) {
            payloadType = PAYLOAD_TYPE.INIT;
        }
        if (chunkIdx === chunkNum) {
            payloadType = PAYLOAD_TYPE.LAST;
        }

        return this.transport
            .send(CLA, instruction, payloadType, 0, chunk, [
                LedgerError.NoErrors,
                LedgerError.DataIsInvalid,
                LedgerError.BadKeyHandle,
                LedgerError.SignVerifyError
            ])
            .then((response: Buffer) => {
                const errorCodeData = response.slice(-2);
                const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
                let errorMessage = errorCodeToString(returnCode);

                let signatureRSV = Buffer.alloc(0);
                let signatureRS = Buffer.alloc(0);

                if (returnCode === LedgerError.BadKeyHandle ||
                    returnCode === LedgerError.DataIsInvalid ||
                    returnCode === LedgerError.SignVerifyError) {
                    errorMessage = `${errorMessage} : ${response
                        .slice(0, response.length - 2)
                        .toString('ascii')}`;
                }

                if (returnCode === LedgerError.NoErrors && response.length > 2) {
                    signatureRSV = response.slice(0, SIGLEN_RSV);
                    signatureRS = response.slice(0, SIGLEN_RS);
                    return {
                        signatureRS,
                        signatureRSV,
                        returnCode: returnCode,
                        errorMessage: errorMessage,
                    };
                }

                return {
                    returnCode: returnCode,
                    errorMessage: errorMessage,
                };

            }, processErrorResponse);
    }

    async sign(path: string, message: Buffer) {
        return this.signGetChunks(path, message).then(chunks => {
            return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_SECP256K1).then(async response => {
                let result = {
                    returnCode: response.returnCode,
                    errorMessage: response.errorMessage,
                    signatureRS: null as null | Buffer,
                    signatureRSV: null as null | Buffer,
                };
                for (let i = 1; i < chunks.length; i += 1) {
                    // eslint-disable-next-line no-await-in-loop
                    result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_SECP256K1);
                    if (result.returnCode !== LedgerError.NoErrors) {
                        break;
                    }
                }
                return result;
            }, processErrorResponse);
        }, processErrorResponse);
    }

    async signMessage(path: string, message: Buffer) {
        return this.signGetChunks(path, message).then(chunks => {
            return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_MESSAGE).then(async response => {
                let result = {
                    returnCode: response.returnCode,
                    errorMessage: response.errorMessage,
                    signatureRS: null as null | Buffer,
                    signatureRSV: null as null | Buffer,
                };
                for (let i = 1; i < chunks.length; i += 1) {
                    // eslint-disable-next-line no-await-in-loop
                    result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_MESSAGE);
                    if (result.returnCode !== LedgerError.NoErrors) {
                        break;
                    }
                }
                return result;
            }, processErrorResponse);
        }, processErrorResponse);
    }

    async signWasmDeploy(path: string, message: Buffer) {
        return this.signGetChunks(path, message).then(chunks => {
            return this.signSendChunk(1, chunks.length, chunks[0], INS.SIGN_WASM_DEPLOY).then(async response => {
                let result = {
                    returnCode: response.returnCode,
                    errorMessage: response.errorMessage,
                    signatureRS: null as null | Buffer,
                    signatureRSV: null as null | Buffer,
                };
                for (let i = 1; i < chunks.length; i += 1) {
                    // eslint-disable-next-line no-await-in-loop
                    result = await this.signSendChunk(1 + i, chunks.length, chunks[i], INS.SIGN_WASM_DEPLOY);
                    if (result.returnCode !== LedgerError.NoErrors) {
                        break;
                    }
                }
                return result;
            }, processErrorResponse);
        }, processErrorResponse);
    }
}
