const { decrypt06, decrypt, unlzss } = require("./build/Release/thrpy-decode.node")

const {
    decrypt06,
    decrypt,
    unlzss
} = thrpyDecode

export {
    thrpyDecode as default,
    decrypt06,
    decrypt,
    unlzss
}