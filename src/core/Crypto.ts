import * as hashUtils from "hash.js";

const pbkdf2 = require('pbkdf2');
const aesjs = require('aes-js');
const aes_salt = 'EpOcWe6ulTd1pKI2fsywukZCwwpVJF1c';


/**
 * @classdesc This class provides the functionality of encryption and decryption
 */
export class Crypto {
    private ivArray: any = [];
    private keyArray: any = [];

    init = (password:string) => {
        this.ivArray =   this.pbkdf2(password,aes_salt,16);
        this.keyArray =  this.pbkdf2(aesjs.utils.hex.fromBytes(this.ivArray),aes_salt,32);
        return {a: this.ivArray, b: this.keyArray}
    };

    encrypt = (textToEncrypt: string): string => {
        const textBytes = aesjs.utils.utf8.toBytes(textToEncrypt);
        const aesCbc = new aesjs.ModeOfOperation.cbc(this.keyArray, this.ivArray);
        const encryptedBytes = aesCbc.encrypt(aesjs.padding.pkcs7.pad(textBytes));
        const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
        return encryptedHex;
    };

    decrypt = (encryptedText: string[] | string | null | undefined): string => {
        const encryptedBytes = aesjs.utils.hex.toBytes(encryptedText);
        const aesCbc = new aesjs.ModeOfOperation.cbc(this.keyArray, this.ivArray);
        const decryptedBytes = aesCbc.decrypt(encryptedBytes);
        const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
        return decryptedText;
    };

    pbkdf2 = (password:string, salt:string , keySize:number) => {
        const iterations = 4096;
        const keyInBytes = keySize;
        const hash = "sha256";
        const passwordKey = pbkdf2.pbkdf2Sync(password, salt, iterations, keyInBytes , hash);
        return passwordKey;
    };

    static hash = (value:string): string => {
        let sha256 = hashUtils.sha256();
        let level1 = sha256.update(value).digest('hex');
        let salted = level1 + aes_salt;
        let level2 = sha256.update(salted).digest('hex');
        let result = sha256.update(level2).digest('hex');
        return result;
    }
}
