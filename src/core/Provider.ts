import { RSAVerifier, ECVerifier, OKPVerifier, ES256KRecoverableVerifier } from './Verifiers';
import { RSASigner, ECSigner, OKPSigner, ES256KRecoverableSigner } from './Signers';
import { Key, RSAKey, OKP, ECKey, KeyInputs } from './JWKUtils';
import { KEY_FORMATS, ALGORITHMS, KTYS } from './globals';
import { DidSiopResponse } from './Response';
import { SigningInfo, JWTObject } from './JWT';
import { Identity, DidDocument } from './Identity';
import { DidSiopRequest } from './Request';
import { checkKeyPair } from './Utils';
import * as ErrorResponse from './ErrorResponse';
import { Crypto } from "./Crypto";
import {Storage} from "./Storage";

export const ERRORS= Object.freeze({
    NO_SIGNING_INFO: 'At least one public key must be confirmed with related private key',
    UNRESOLVED_IDENTITY: 'Unresolved identity',
    NO_PUBLIC_KEY: 'No public key matches given private key',
});

/**
 * @classdesc This class provides the functionality of a DID based Self Issued OpenID Connect Provider
 * @property {Identity} identity  - Used to store Decentralized Identity information of the Provider (end user)
 * @property {SigningInfo[]} signing_info_set - Used to store a list of cryptographic information used to sign id_tokens
 * @property {Crypto} crypto - Used to generate and decrypt authorization codes
 */
export class Provider{
    private identity: Identity = new Identity();
    private signing_info_set: SigningInfo[] = [];
    private crypto: Crypto = new Crypto();
    private storage:Storage = new Storage();

    setStorage = (storage:any) => {
        this.storage.setStorage(storage);
    };

    /**
     * @param {string} did - The DID of the provider (end user)
     * @param {DidDocument} [doc] - DID Document of the provider (end user).
     * @remarks This method is used to set the decentralized identity for the provider (end user).
     * doc parameter is optional and if provided it will be used to directly set the identity.
     * Otherwise the DID Document will be resolved over a related network.
     */
    async setUser(did: string, doc?: DidDocument){
        try {
            if(doc){
                this.identity.setDocument(doc, did);
            }
            else{
                await this.identity.resolve(did);
            }
        } catch (err) {
            throw err;
        }
    }

    /**
     * @param {string} key - Private part of any cryptographic key listed in the 'authentication' field of the user's DID Document
     * @param {string} [kid] - kid value of the key. Optional and not used
     * @param {KEY_FORMATS| string} [format] - Format in which the private key is supplied. Optional and not used
     * @param {ALGORITHMS} [algorithm] - Algorithm to use the key with. Optional and not used
     * @returns {string} - kid of the added key
     * @remarks This method is used to add signing information to 'signing_info_set'.
     * All optional parameters are not used and only there to make the library backward compatible.
     * Instead of using those optional parameters, given key is iteratively tried with
     * every public key listed in the 'authentication' field of RP's DID Document and every key format
     * until a compatible combination of those information which can be used for the signing process is found.
     */
    addSigningParams(key: string, kid?: string, format?: KEY_FORMATS | string, algorithm?: ALGORITHMS | string): string{
        try{
            if(format){}
            if(algorithm){}
            if(kid){}

            let didPublicKeySet = this.identity.extractAuthenticationKeys();

            for(let didPublicKey of didPublicKeySet){
                let publicKeyInfo: KeyInputs.KeyInfo = {
                    key: didPublicKey.publicKey,
                    kid: didPublicKey.id,
                    use: 'sig',
                    kty: KTYS[didPublicKey.kty],
                    alg: ALGORITHMS[didPublicKey.alg],
                    format: didPublicKey.format,
                    isPrivate: false
                }

                for(let key_format in KEY_FORMATS){

                    let privateKeyInfo: KeyInputs.KeyInfo = {
                        key: key,
                        kid: didPublicKey.id,
                        use: 'sig',
                        kty: KTYS[didPublicKey.kty],
                        alg: ALGORITHMS[didPublicKey.alg],
                        format: KEY_FORMATS[key_format as keyof typeof KEY_FORMATS],
                        isPrivate: true
                    }

                    let privateKey: Key;
                    let publicKey: Key | string;
                    let signer, verifier;

                    try{
                        switch(didPublicKey.kty){
                            case KTYS.RSA: {
                                privateKey = RSAKey.fromKey(privateKeyInfo);
                                publicKey = RSAKey.fromKey(publicKeyInfo);
                                signer = new RSASigner();
                                verifier = new RSAVerifier();
                                break;
                            };
                            case KTYS.EC: {
                                if(didPublicKey.format === KEY_FORMATS.ETHEREUM_ADDRESS){
                                    privateKey = ECKey.fromKey(privateKeyInfo);
                                    publicKey = didPublicKey.publicKey;
                                    signer = new ES256KRecoverableSigner();
                                    verifier = new ES256KRecoverableVerifier();
                                }
                                else{
                                    privateKey = ECKey.fromKey(privateKeyInfo);
                                    publicKey = ECKey.fromKey(publicKeyInfo);
                                    signer = new ECSigner();
                                    verifier = new ECVerifier();
                                }
                                break;
                            }
                            case KTYS.OKP: {
                                privateKey = OKP.fromKey(privateKeyInfo);
                                publicKey = OKP.fromKey(publicKeyInfo);
                                signer = new OKPSigner();
                                verifier = new OKPVerifier();
                                break;
                            };
                            default:{
                                continue;
                            }
                        }

                        if(checkKeyPair(privateKey, publicKey, signer, verifier, didPublicKey.alg)){
                            this.signing_info_set.push({
                                alg: didPublicKey.alg,
                                kid: didPublicKey.id,
                                key: key,
                                format: KEY_FORMATS[key_format as keyof typeof KEY_FORMATS],
                            });
                            if(didPublicKey.id){
                                this.crypto.init(key);
                            }
                            return didPublicKey.id;
                        }
                    }
                    catch(err){
                        continue;
                    }
                }
            }

            throw new Error(ERRORS.NO_PUBLIC_KEY);
        }
        catch(err){
            throw err;
        }
    }

    /**
     * @param {string} kid - kid value of the SigningInfo which needs to be removed from the list
     * @remarks This method is used to remove a certain SigningInfo (key) which has the given kid value from the list.
     */
    removeSigningParams(kid: string){
        try{
            this.signing_info_set = this.signing_info_set.filter(s => { return s.kid !== kid });
        }
        catch(err){
            throw err;
        }
    }

    /**
     * @param {string} request - A DID SIOP request
     * @returns {Promise<JWT.JWTObject>} - A Promise which resolves to a decoded request JWT
     * @remarks This method is used to validate requests coming from Relying Parties.
     */
    async validateRequest(request: string): Promise<JWTObject | any>{
        try {
            return DidSiopRequest.validateRequest(request);
        } catch (err) {
            return Promise.reject(err);
        }
    }

    /**
     * @param {any} decodedRequest - Decoded request JWT for which a response needs to be generated
     * @param {string} request - DID SIOP request containing the request payload
     * @param {number} expiresIn - Number of milliseconds under which the generated response is valid. Relying Parties can
     * either consider this value or ignore it
     * @returns {Promise<string>} - A Promise which resolves to an object which contains response_type and data.
     * data could be authorization code or encoded DID SIOP response JWT
     * @remarks This method is used to generate a response to a given DID SIOP request (for both implicit and authorization code flow)
     */
    async generateResponse(decodedRequest: any, request:string, expiresIn: number = 1000): Promise<string>{
        try{
            if(this.signing_info_set.length > 0){
                let signing_info = this.signing_info_set[Math.floor(Math.random() * this.signing_info_set.length)];

                if(this.identity.isResolved()){
                    return await DidSiopResponse.generateResponse(decodedRequest, signing_info, this.identity, expiresIn, this.crypto, request, this.storage);
                }
                else{
                    return Promise.reject(new Error(ERRORS.UNRESOLVED_IDENTITY));
                }
            }
            return Promise.reject(new Error(ERRORS.NO_SIGNING_INFO));
        }
        catch(err){
            return Promise.reject(err);
        }
    }

    /**
     * @param {string} errorMessage - Message of a specific SIOPErrorResponse
     * @returns {string} - Encoded SIOPErrorResponse object
     * @remarks This method is used to generate error responses.
     */
    generateErrorResponse(errorMessage: string): string{
        try{
            return ErrorResponse.getBase64URLEncodedError(errorMessage);
        }
        catch(err){
            throw err;
        }
    }
}
