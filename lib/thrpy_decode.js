const assert = require("assert")

const ZUN_LZSS_PARAMS = { 
    indexSize: 13,
    lengthSize: 4,
    minLength: 3,
    initialWriteIndex: 1
}

function th06DecryptImpl(buffer, key, start) {
    const newBuffer = Buffer.from(buffer)
    for (let i = start; i < buffer.length; i++) {
        newBuffer[i] -= key
        key += 7
    }
}

function thDecryptImpl(buffer, blockSize, base, add) {
    const newBuffer = Buffer.from(buffer);
    let left = buffer.length;

    if ((left % blockSize) < (blockSize / 4))
        left -= left % blockSize;

    if (left)
        left -= buffer.length & 1;

    while (left) {
        if (left < blockSize)
            blockSize = left;

        let p = 0
        let tp1 = p + blockSize - 1;
        let tp2 = p + blockSize - 2;
        let hf = (blockSize + (blockSize & 0x1)) / 2;

        for (let i = 0; i < hf; ++i, ++p) {
            newBuffer[tp1] = tbuf[p] ^ base;
            base += add;
            tp1 -= 2;
        }
        hf = blockSize / 2;

        for (let i = 0; i < hf; ++i, ++p) {
            newBuffer[tp2] = tbuf[p] ^ base;
            base += add;
            tp2 -= 2;
        }
        left -= blockSize;
    }

    return newBuffer
}

function thUnlzssImpl(buffer, params = ZUN_LZSS_PARAMS) {
    class BitIterator {
        index = 0
        data = []

        constructor(buffer) {
            for (let i = 0; i < buffer.length; i++) {
                this.data.push(buffer[i] & 0b10000000)
                this.data.push(buffer[i] & 0b01000000)
                this.data.push(buffer[i] & 0b00100000)
                this.data.push(buffer[i] & 0b00010000)
                this.data.push(buffer[i] & 0b00001000)
                this.data.push(buffer[i] & 0b00000100)
                this.data.push(buffer[i] & 0b00000010)
                this.data.push(buffer[i] & 0b00000001)
            }
        }

        take(n) {
            let ret = 0
            for (let i = 0; i < n; i++) {
                if (this.index >= this.data.length)
                    return ret
                if (this.data[this.index])
                    ret |= 1 << (n - i - 1)
                this.index++
            }
            return ret
        }
    }

    const inputBits = new BitIterator(buffer)
    let history = new Array(1 << params.indexSize).fill(0)
    let historyWriteIndex = params.initialWriteIndex
    const outputBytes = []

    function putOutputByte(byte) {
        outputBytes.push(byte)
        history[historyWriteIndex] = byte
        historyWriteIndex = (historyWriteIndex + 1) % history.length
    }

    while (true) {
        let controlBit = inputBits.take(1)
        if (controlBit) {
            let dataByte = inputBits.take(8)
            putOutputByte(dataByte)
        } else {
            let readFrom = inputBits.take(params.indexSize)
            if (!readFrom)
                break

            let readCount = inputBits.take(params.lengthSize) + params.minLength
            for (let i = 0; i < readCount; i++) {
                putOutputByte(history[readFrom])
                readFrom = (readFrom + 1) % history.length
            }
        }
    }

    if (inputBits.data.length !== inputBits.index) {
        throw new Error("The provided LZSS data is invalid or the LZSS parameters are wrong")
    }

    return outputBytes
}

export function decrypt06(buffer, key, start = 0) {
    return th06DecryptImpl(buffer, key, start)
}

export function decrypt(buffer, blockSize, base, add) {
    const vBuffer = thDecryptImpl(buffer.subarray(), blockSize, base, add)
    
    assert(buffer.length === vBuffer.length)
    return vBuffer
}

export function unlzss(buffer) {
    return thUnlzssImpl(buffer)
}
