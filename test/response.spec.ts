// @ts-ignore
import mockAsyncStorage from '@react-native-async-storage/async-storage/jest/async-storage-mock';
jest.mock('@react-native-async-storage/async-storage', () => mockAsyncStorage);
import { DidSiopResponse } from './../src/core/Response';
import { Identity } from './../src/core/Identity';
import { SigningInfo } from './../src/core/JWT';
import { ALGORITHMS, KEY_FORMATS } from '../src/core/globals';
import nock from 'nock';
import {Crypto} from "../src/core/Crypto";
import {jwtGoodDecoded} from "./request.spec.resources";
const privateKey = 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964';
// const authCode = 'af39a7ff0ed5389f7dfe7ac5ff4b51acf47d0917343395873ff47a1e936f57e27b2dd823697d6b7cec7174df370c3a23648f2dc9a0fba7cc66629e3b142a07ddd809dba98d450596fbb6e1cffb8e4cd8dd370597630e810b259c5c2c8e7c476ddf9813041d46d7c8af3f17a54f8313da7f6bee1b7cfeb036e70ddc04d47e70e7'


let rpDidDoc = {
    didDocument: {
        "@context": "https://w3id.org/did/v1",
        "id": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
        "authentication": [
        {
            "type": "Secp256k1SignatureAuthentication2018",
            "publicKey": [
            "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#controller"
            ]
        }
        ],
        "publicKey": [
        {
            "id": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#controller",
            "type": "Secp256k1VerificationKey2018",
            "ethereumAddress": "0xb07ead9717b44b6cf439c474362b9b0877cbbf83",
            "owner": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83"
        }
        ]
    }
}
let rpDID = 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83';

let userDidDoc = {
    didDocument: {
        "@context": "https://w3id.org/did/v1",
        "id": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf",
        "authentication": [
        {
            "type": "Secp256k1SignatureAuthentication2018",
            "publicKey": [
            "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#controller"
            ]
        }
        ],
        "publicKey": [
        {
            "id": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf#controller",
            "type": "Secp256k1VerificationKey2018",
            "ethereumAddress": "0x30d1707aa439f215756d67300c95bb38b5646aef",
            "owner": "did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf"
        }
        ]
    }
  }
let userDID = 'did:ethr:0x30D1707AA439F215756d67300c95bB38B5646aEf';

describe("Response", function () {
    beforeEach(() => {
        nock('https://uniresolver.io/1.0/identifiers').persist().get('/'+rpDID).reply(200, rpDidDoc).get('/'+userDID).reply(200, userDidDoc);
    });
    test("Response generation and validation", async () => {
        jest.setTimeout(7000);
        const crypto = new Crypto();
        crypto.init(privateKey);

        const request = 'openid://?client_id=https%3A%2F%2Fmy.rp.com%2Fcb&request=eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpldGhyOjB4QjA3RWFkOTcxN2I0NEI2Y0Y0MzljNDc0MzYyYjlCMDg3N0NCQkY4MyNjb250cm9sbGVyIn0.eyJpc3MiOiJkaWQ6ZXRocjoweEIwN0VhZDk3MTdiNDRCNmNGNDM5YzQ3NDM2MmI5QjA4NzdDQkJGODMiLCJzY29wZSI6Im9wZW5pZCBkaWRfYXV0aG4iLCJjbGllbnRfaWQiOiJodHRwczovL215LnJwLmNvbS9jYiIsInJlZ2lzdHJhdGlvbiI6eyJqd2tzX3VyaSI6Imh0dHBzOi8vdW5pcmVzb2x2ZXIuaW8vMS4wL2lkZW50aWZpZXJzL2RpZDpleGFtcGxlOjB4YWI7dHJhbnNmb3JtLWtleXM9andrcyIsImlkX3Rva2VuX3NpZ25lZF9yZXNwb25zZV9hbGciOlsiRVMyNTZLIiwiRWREU0EiLCJSUzI1NiJdfSwic3RhdGUiOiJhZjBpZmpzbGRraiIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwicmVzcG9uc2VfbW9kZSI6ImZvcm1fcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJpZF90b2tlbiJ9.G3kG77qXciUNX-uNjLfwV4HCJYjeJNt7T04PCXKlt9Np1Sf8Bd4WhdKyy5-aZAFFwahF93VWeE-NeGcU2UAIgAE&response_type=id_token&scope=openid%20did_authn'
        let requestPayload = {
            "iss": "did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83",
            "response_type": "id_token",
            "client_id": "https://my.rp.com/cb",
            "scope": "openid did_authn",
            "state": "af0ifjsldkj",
            "nonce": "n-0S6_WzA2Mj",
            "response_mode": "form_post",
            "registration": {
                "jwks_uri": "https://uniresolver.io/1.0/identifiers/did:example:0xab;transform-keys=jwks",
                "id_token_signed_response_alg": ["ES256K", "ES256K-R", "EdDSA", "RS256"]
            }
        };

        let signing: SigningInfo = {
            alg: ALGORITHMS["ES256K-R"],
            key: 'CE438802C1F0B6F12BC6E686F372D7D495BC5AA634134B4A7EA4603CB25F0964',
            kid: 'did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83#controller',
            format: KEY_FORMATS.HEX,
        };

        let user = new Identity();
        await user.resolve('did:ethr:0xB07Ead9717b44B6cF439c474362b9B0877CBBF83');
        let response = await DidSiopResponse.generateResponse(requestPayload, signing, user, 5000, crypto, request);
        console.log(response);
        //
        // let checkParams = {
        //     redirect_uri: 'https://my.rp.com/cb',
        //     nonce: "n-0S6_WzA2Mj",
        //     validBefore: 1000,
        //     isExpirable: true,
        // }
        // let validity = await DidSiopResponse.validateResponse(response, checkParams);
        // expect(validity).toBeTruthy();
    });
    test("Auth code generation", async () => {
        const crypto = new Crypto();
        crypto.init(privateKey);
        const authCode = await DidSiopResponse.generateAuthorizationCode(jwtGoodDecoded, crypto);
        console.log(authCode);
        expect(authCode).toBeTruthy();
    });
    // test("Auth code validation", async () => {
    //     const crypto = new Crypto();
    //     crypto.init(privateKey);
    //     const dd = requests.good.requestGoodAuthenticationFlow + authCode;
    //     console.log(dd)
    //     const valid = await DidSiopResponse.validateAuthorizationCode(dd, jwtGoodDecoded, crypto);
    //     console.log(valid);
    //     expect(dd).toBeTruthy();
    // });
    // test("Refresh_token generation", async () => {
    //     const crypto = new Crypto();
    //     crypto.init(privateKey);
    //     const authCode = await DidSiopResponse.generateRefreshToken(, crypto);
    //     console.log(authCode);
    //     expect(authCode).toBeTruthy();
    // });
});
