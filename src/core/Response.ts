import {ALGORITHMS, KTYS, KEY_FORMATS} from './globals';
import * as JWT from './JWT';
import {Identity} from './Identity';
import {KeyInputs, Key, RSAKey, ECKey, OKP, calculateThumbprint} from './JWKUtils';
import base64url from 'base64url';
import {Crypto} from "./Crypto";
import * as ErrorResponse from './ErrorResponse';
import * as queryString from "query-string";
import Storage from "./Storage";

const ERRORS = Object.freeze({
    UNSUPPORTED_ALGO: 'Algorithm not supported',
    PUBLIC_KEY_ERROR: 'Cannot resolve public key',
    KEY_MISMATCH: 'Signing key does not match kid',
    MALFORMED_JWT_ERROR: 'Malformed response jwt',
    NON_SIOP_FLOW: 'Response jwt is not compatible with SIOP flow',
    INCORRECT_AUDIENCE: 'Incorrect audience',
    INCORRECT_NONCE: 'Incorrect nonce',
    NO_ISSUED_TIME: 'No iat in jwt',
    NO_EXPIRATION: 'No exp in jwt',
    JWT_VALIDITY_EXPIRED: 'JWT validity has expired',
    INVALID_JWK_THUMBPRINT: 'Invalid sub (sub_jwk thumbprint)',
    INVALID_SIGNATURE_ERROR: 'Invalid signature error',
});

export interface CheckParams {
    redirect_uri: string;
    nonce?: string;
    validBefore?: number;
    isExpirable?: boolean;
}

/**
 * @classdesc This class contains static methods related to DID SIOP response generation and validation
 */
export class DidSiopResponse {
    /**
     * @param {any} requestPayload - Payload of the request JWT. Some information from this object is needed in constructing the response
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * @param {number} [expiresIn = 1000] - Amount of time under which generated id_token (response) is valid. The party which validate the
     * response can either consider this value or ignore it
     * @returns {Promise<string>} - A promise which resolves to a response (id_token) (JWT)
     * @remarks This method first checks if given SigningInfo is compatible with the algorithm required by the RP in
     * 'requestPayload.registration.id_token_signed_response_alg' field.
     * Then it proceeds to extract provider's (user) public key from 'didSiopUser' param using 'kid' field in 'signingInfo' param.
     * Finally it will create the response JWT (id_token) with relevant information, sign it using 'signingInfo' and return it.
     * https://identity.foundation/did-siop/#generate-siop-response
     */
    static async generateResponse(requestPayload: any, signingInfo: JWT.SigningInfo, didSiopUser: Identity, expiresIn: number = 1000, crypto:Crypto, request:string): Promise<string> {
        try {
            let sendResponse:boolean = false;
            let parsed = queryString.parseUrl(request);
            if(requestPayload.response_type === 'code'){
                if(parsed.query.grant_type === 'authorization_code'){
                    const validCode:string = await this.validateAuthorizationCode(request, requestPayload, crypto);
                    if(validCode){
                        sendResponse = true
                    }else{
                        return validCode;
                    }
                }else{
                    const code = this.generateAuthorizationCode(requestPayload,crypto);
                    return code
                }
            }else{
                sendResponse = true;
            }
            if(sendResponse){
                let header: JWT.JWTHeader;
                let alg = '';

                if (requestPayload.registration.id_token_signed_response_alg.includes(ALGORITHMS[signingInfo.alg])) {
                    alg = ALGORITHMS[signingInfo.alg];
                } else {
                    Promise.reject(ERRORS.UNSUPPORTED_ALGO);
                }

                let didPubKey = didSiopUser.extractAuthenticationKeys().find(authKey => {
                    return authKey.id === signingInfo.kid
                });
                header = {
                    typ: 'JWT',
                    alg: alg,
                    kid: signingInfo.kid,
                }

                let publicKey: Key | undefined;

                let keyInfo: KeyInputs.KeyInfo;

                if (didPubKey) {
                    keyInfo = {
                        key: didPubKey.publicKey,
                        kid: didPubKey.id,
                        use: 'sig',
                        kty: KTYS[didPubKey.kty],
                        format: didPubKey.format,
                        isPrivate: false,
                    }

                    switch (didPubKey.kty) {
                        case KTYS.RSA:
                            publicKey = RSAKey.fromKey(keyInfo);
                            break;
                        case KTYS.EC: {
                            if (didPubKey.format === KEY_FORMATS.ETHEREUM_ADDRESS) {
                                keyInfo.key = signingInfo.key;
                                keyInfo.format = signingInfo.format;
                                keyInfo.isPrivate = true;
                            }
                            publicKey = ECKey.fromKey(keyInfo);
                            break;
                        }
                        case KTYS.OKP:
                            publicKey = OKP.fromKey(keyInfo);
                            break;
                    }
                } else {
                    return Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR));
                }

                let payload: any = {
                    iss: 'https://self-issued.me',
                }

                payload.did = didSiopUser.getDocument().id;
                if (requestPayload.client_id) payload.aud = requestPayload.client_id;

                if (publicKey) {
                    payload.sub_jwk = publicKey.getMinimalJWK();
                    payload.sub = calculateThumbprint(publicKey.getMinimalJWK());
                } else {
                    return Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR));
                }

                if (requestPayload.nonce) payload.nonce = requestPayload.nonce;
                if (requestPayload.state) payload.state = requestPayload.state;

                payload.iat = Date.now();
                payload.exp = Date.now() + expiresIn;

                let unsigned: JWT.JWTObject = {
                    header: header,
                    payload: payload,
                }

                return JWT.sign(unsigned, signingInfo);
            }else {
                return ""
            }

        } catch (err) {
            return Promise.reject(err);
        }
    }

    /**
     *
     * @param {string} response - A DID SIOP response which needs to be validated
     * @param {CheckParams} checkParams - Specific field values in the JWT which needs to be validated
     * @returns {Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse>} - A promise wich will resolve either to a decoded id_token (JWT)
     * or an error response
     * @remarks This method first decodes the response JWT.
     * Then checks if it is an error response and if so, returns it.
     * Else it will proceed to validate the JWT (id_token).
     * Fields in the JWT header and payload will be checked for availability.
     * Then the id_token will be validated against 'checkParams'.
     * Then the signature of the id_token is verified using public key information derived from
     * the 'kid' field in the header and 'did' field in the payload.
     * If the verification is successful, this method returns the decoded id_token (JWT).
     * https://identity.foundation/did-siop/#siop-response-validation
     */
    static async validateResponse(response: string, checkParams: CheckParams): Promise<JWT.JWTObject | ErrorResponse.SIOPErrorResponse> {
        let decodedHeader: JWT.JWTHeader;
        let decodedPayload;
        try {
            let errorResponse = ErrorResponse.checkErrorResponse(response);
            if (errorResponse) return errorResponse;

            decodedHeader = JSON.parse(base64url.decode(response.split('.')[0]));
            decodedPayload = JSON.parse(base64url.decode(response.split('.')[1]));
        } catch (err) {
            return Promise.reject(err);
        }

        if (
            (decodedHeader.kid && !decodedHeader.kid.match(/^ *$/)) &&
            (decodedPayload.iss && !decodedPayload.iss.match(/^ *$/)) &&
            (decodedPayload.aud && !decodedPayload.aud.match(/^ *$/)) &&
            (decodedPayload.did && !decodedPayload.did.match(/^ *$/)) &&
            (decodedPayload.sub && !decodedPayload.sub.match(/^ *$/)) &&
            (decodedPayload.sub_jwk && !JSON.stringify(decodedPayload.sub_jwk).match(/^ *$/))
        ) {
            if (decodedPayload.iss !== 'https://self-issued.me') return Promise.reject(new Error(ERRORS.NON_SIOP_FLOW));

            if (decodedPayload.aud !== checkParams.redirect_uri) return Promise.reject(new Error(ERRORS.INCORRECT_AUDIENCE));

            if (decodedPayload.nonce && (decodedPayload.nonce !== checkParams.nonce)) return Promise.reject(new Error(ERRORS.INCORRECT_NONCE));

            if (checkParams.validBefore) {
                if (decodedPayload.iat) {
                    if (decodedPayload.iat + checkParams.validBefore <= Date.now()) return Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED));
                } else {
                    return Promise.reject(new Error(ERRORS.NO_ISSUED_TIME));
                }
            }

            if (checkParams.isExpirable) {
                if (decodedPayload.exp) {
                    if (decodedPayload.exp <= Date.now()) return Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED));
                } else {
                    return Promise.reject(new Error(ERRORS.NO_EXPIRATION));
                }
            }

            let jwkThumbprint = calculateThumbprint(decodedPayload.sub_jwk);
            if (jwkThumbprint !== decodedPayload.sub) return Promise.reject(new Error(ERRORS.INVALID_JWK_THUMBPRINT));

            let publicKeyInfo: JWT.SigningInfo | undefined;
            try {
                let identity = new Identity();
                await identity.resolve(decodedPayload.did);

                let didPubKey = identity.extractAuthenticationKeys().find(authKey => {
                    return authKey.id === decodedHeader.kid
                });

                if (didPubKey) {
                    publicKeyInfo = {
                        key: didPubKey.publicKey,
                        kid: didPubKey.id,
                        alg: didPubKey.alg,
                        format: didPubKey.format
                    }
                } else {
                    throw new Error(ERRORS.PUBLIC_KEY_ERROR);
                }
            } catch (err) {
                return Promise.reject(ERRORS.PUBLIC_KEY_ERROR);
            }

            let validity: boolean = false;
            if (publicKeyInfo) {
                validity = JWT.verify(response, publicKeyInfo);
            } else {
                return Promise.reject(ERRORS.PUBLIC_KEY_ERROR);
            }

            if (validity) return {
                header: decodedHeader,
                payload: decodedPayload,
            }

            return Promise.reject(new Error(ERRORS.INVALID_SIGNATURE_ERROR));
        } else {
            return Promise.reject(new Error(ERRORS.MALFORMED_JWT_ERROR));
        }
    }

    /**
     *
     * @param {string} request - A validated request
     * @returns {Promise<string>} - A promise wich will resolve either to a authorization code
     * or an error response
     * @remarks This method generates authorization code for authentication flow.
     * First it hashes the SIOP request
     * Then an object with fields iat, exp and request is created(hashed request is used as the request);
     * Encrypt the object by a key generated by private key of provider to obtain the authentication code.
     *
     */

    static async generateAuthorizationCode(requestObject: any, crypto: Crypto): Promise<string> {
        try {
            const hashedRequest = Crypto.hash(JSON.stringify(requestObject));
            const authCode = {
                iat: Date.now(),
                exp: Date.now() + 1000 * 60 * 10,
                request: hashedRequest
            };
            const authCodeEncrypted = crypto.encrypt(JSON.stringify(authCode));
            return authCodeEncrypted;
        } catch (err) {
            return Promise.reject(new Error(err));
        }
    }

    static async validateAuthorizationCode(request: string, requestObject: any, crypto: Crypto): Promise<string> {
        try {
            let parsed = queryString.parseUrl(request);
            const authCode = parsed.query.code;
            const authCodeDecrypted  = crypto.decrypt(authCode);
            const reqObject = JSON.parse(authCodeDecrypted);
            const hashedReq = Crypto.hash(JSON.stringify(requestObject));
            const alreadyUsed = await Storage.getItem(reqObject.iat);
            if (hashedReq != reqObject.request) {
                return Promise.reject(new Error('INVALID REQUEST'));
            }
            else if (reqObject.exp < Date.now()) {
                return Promise.reject(new Error('EXPIRED AUTHORIZATION CODE'));
            }
            else if(alreadyUsed){
                return Promise.reject(new Error('ALREADY USED CODE'));
            }
            else{
                await Storage.setItem(reqObject.iat,reqObject.request);
                return Promise.resolve('True');
            }
        } catch (err) {
            if( err.message === 'invalid ciphertext size (must be multiple of 16 bytes)'){
                return Promise.reject(new Error('INVALID AUTH CODE'));
            }else{
                return Promise.reject(err);
            }
        }
    }
}

