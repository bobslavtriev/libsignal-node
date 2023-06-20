const nodeCrypto = require('crypto');

function assertBuffer(value) {
    if (!(value instanceof Buffer)) {
        throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
    }
    return value;
}

async function encrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = await nodeCrypto.webcrypto.subtle.importKey("raw", key, {
        name: "AES-CBC"
    }, false, ["encrypt"]);
    return Buffer.from(await nodeCrypto.webcrypto.subtle.encrypt({
        name: "AES-CBC",
        iv
    }, cipher, data));
}

async function decrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = await nodeCrypto.webcrypto.subtle.importKey("raw", key, {
        name: "AES-CBC"
    }, false, ["decrypt"]);
    return Buffer.from(await nodeCrypto.webcrypto.subtle.decrypt({
        name: "AES-CBC",
        iv
    }, decipher, data));
}

// sign
async function calculateMAC(key, data) {
    assertBuffer(key);
    assertBuffer(data);
    const hmac = await nodeCrypto.subtle.importKey("raw", key, {
        name: "HMAC",
        hash: {
            name: "SHA-256"
        }
    }, false, ["sign"]);
    return Buffer.from(await nodeCrypto.webcrypto.subtle.sign({
        name: "HMAC",
        hash: "SHA-256"
    }, hmac, data));
}

async function hash(data) {
    assertBuffer(data);
    return Buffer.from(await nodeCrypto.webcrypto.subtle.digest({
        name: "SHA-512"
    }, data));
}

async function deriveSecrets(input, salt, info) {
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }
    const PRK = await calculateMAC(salt, input);
    const infoArray = new Uint8Array(info.byteLength + 1 + 32);
    infoArray.set(info, 32);
    infoArray[infoArray.length - 1] = 1;
    const signeds = [await calculateMAC(PRK, Buffer.from(infoArray.slice(32)))];
    infoArray.set(signeds[0]);
    infoArray[infoArray.length - 1] = 2;
    signeds.push(await calculateMAC(PRK, Buffer.from(infoArray)));
    infoArray.set(signeds[1]);
    infoArray[infoArray.length - 1] = 3;
    signeds.push(await calculateMAC(PRK, Buffer.from(infoArray)));
    return signeds;
}

async function verifyMAC(data, key, mac, length) {
    const calculatedMac = await calculateMAC(key, data);
    if (mac.byteLength != length || calculatedMac.byteLength < length) {
        throw new Error("Bad MAC length");
    }
    let verified = 0;
    for (let i = 0; i < mac.byteLength; ++i) {
        verified |= calculatedMac[i] ^ mac[i];
    }
    if (verified !== 0) {
        throw new Error("Bad MAC");
    }
}

module.exports = {
    encrypt,
    decrypt,
    calculateMAC,
    hash,
    deriveSecrets,
    verifyMAC
};