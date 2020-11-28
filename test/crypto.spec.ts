import {Crypto} from "../src/core/Crypto";

const privateKey = 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964';

describe("Crypto class", function () {
    test("init", async () => {
        const crypto = new Crypto();
        const key = crypto.init(privateKey);
        expect(key).toBeTruthy();
    });
    test("encrypt",  () => {
        const crypto = new Crypto();
        crypto.init(privateKey);
        const encrypted = crypto.encrypt('TextMustBe16BytesNoTextMustBe16BytesNo');
        console.log(encrypted);
        expect(encrypted).toBeTruthy();
    });
    test("encrypt/decrypt",  () => {
        const crypto = new Crypto();
        crypto.init(privateKey);
        const encrypted = crypto.encrypt('TextMustBe16BytesNo  ');
        const decrypted =  crypto.decrypt(encrypted);
        console.log(decrypted.length);
        expect(decrypted).toBeTruthy();
    });
});
