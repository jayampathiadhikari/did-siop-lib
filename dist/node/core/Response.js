"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DidSiopResponse = void 0;
var globals_1 = require("./globals");
var JWT = __importStar(require("./JWT"));
var Identity_1 = require("./Identity");
var JWKUtils_1 = require("./JWKUtils");
var base64url_1 = __importDefault(require("base64url"));
var Crypto_1 = require("./Crypto");
var ErrorResponse = __importStar(require("./ErrorResponse"));
var queryString = __importStar(require("query-string"));
var ERRORS = Object.freeze({
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
    TOKEN_MISMATCH: 'id_token does not match with refresh_token',
    EXPIRED_REFRESH_TOKEN: 'Expired refresh token'
});
/**
 * @classdesc This class contains static methods related to DID SIOP response generation and validation
 */
var DidSiopResponse = /** @class */ (function () {
    function DidSiopResponse() {
    }
    /**
     * @param {any} decodedRequest - Decoded request JWT. Some information from this object is needed in constructing the response
     * @param {JWT.SigningInfo} signingInfo - Key information used to sign the response JWT
     * @param {Identity} didSiopUser - Used to retrieve the information about the provider (user DID) which are included in the response
     * @param {number} [expiresIn = 1000] - Amount of time under which generated id_token (response) is valid. The party which validate the
     * response can either consider this value or ignore it
     * @param {Crypto} crypto - Used to generate and decrypt authorization codes
     * @param {string} request - DID SIOP request containing the request payload
     * @returns {Promise<string>} - A promise which resolves to a response depending on the request type (example responses -
     * {"response_type":"code", "code":"auth_code"}
     * {"response_type":"id_token", "id_token":"token"}
     * {"response_type":"id_token", "id_token":"token", "refresh_token":"token"}
     * )
     * @remarks This method first checks the flow type of the request. if its authorization code then it generates or validates the auth code if given.
     * then if the auth code is valid or flow type is grant, it works as follows.
     * if given SigningInfo is compatible with the algorithm required by the RP in 'requestPayload.registration.id_token_signed_response_alg' field.
     * Then it proceeds to extract provider's (user) public key from 'didSiopUser' param using 'kid' field in 'signingInfo' param.
     * Finally it will create the response JWT (id_token) with relevant information, sign it using 'signingInfo' and return it.
     * https://identity.foundation/did-siop/#generate-siop-response
     */
    DidSiopResponse.generateResponse = function (decodedRequest, signingInfo, didSiopUser, expiresIn, crypto, request, storage, vc) {
        if (expiresIn === void 0) { expiresIn = 1000; }
        return __awaiter(this, void 0, void 0, function () {
            var requestHeader, requestPayload, sendResponse, parsed, validCode, code, idToken, refreshToken, res, unsigned, idToken_1, refreshToken_1, header, alg, didPubKey, publicKey, keyInfo, payload, now, unsigned, idToken, refreshToken, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 16, , 17]);
                        requestHeader = decodedRequest.header;
                        requestPayload = decodedRequest.payload;
                        sendResponse = false;
                        parsed = queryString.parseUrl(request);
                        if (!(requestPayload.response_type === 'code')) return [3 /*break*/, 5];
                        if (!(parsed.query.grant_type === 'authorization_code')) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.validateAuthorizationCode(request, requestPayload, crypto, storage)];
                    case 1:
                        validCode = _a.sent();
                        if (validCode) {
                            sendResponse = true;
                        }
                        else {
                            return [2 /*return*/, validCode];
                        }
                        return [3 /*break*/, 4];
                    case 2: return [4 /*yield*/, this.generateAuthorizationCode(requestPayload, crypto)];
                    case 3:
                        code = _a.sent();
                        return [2 /*return*/, JSON.stringify({ response_type: 'code', code: code })];
                    case 4: return [3 /*break*/, 10];
                    case 5:
                        if (!(parsed.query.grant_type === 'refresh_token')) return [3 /*break*/, 9];
                        idToken = parsed.query.id_token;
                        refreshToken = parsed.query.refresh_token;
                        return [4 /*yield*/, this.validateRefreshToken(idToken, refreshToken, crypto)];
                    case 6:
                        res = _a.sent();
                        if (!(res === 'true')) return [3 /*break*/, 8];
                        requestPayload.iat = Date.now();
                        requestPayload.exp = Date.now() + expiresIn;
                        unsigned = {
                            header: requestHeader,
                            payload: requestPayload,
                        };
                        idToken_1 = JWT.sign(unsigned, signingInfo);
                        return [4 /*yield*/, this.generateRefreshToken(idToken_1, crypto)];
                    case 7:
                        refreshToken_1 = _a.sent();
                        return [2 /*return*/, JSON.stringify({ response_type: 'id_token', id_token: idToken_1, refresh_token: refreshToken_1 })];
                    case 8: return [2 /*return*/, res];
                    case 9:
                        sendResponse = true;
                        _a.label = 10;
                    case 10:
                        if (!sendResponse) return [3 /*break*/, 14];
                        header = void 0;
                        alg = '';
                        if (requestPayload.registration.id_token_signed_response_alg.includes(globals_1.ALGORITHMS[signingInfo.alg])) {
                            alg = globals_1.ALGORITHMS[signingInfo.alg];
                        }
                        else {
                            Promise.reject(ERRORS.UNSUPPORTED_ALGO);
                        }
                        didPubKey = didSiopUser.extractAuthenticationKeys().find(function (authKey) {
                            return authKey.id === signingInfo.kid;
                        });
                        header = {
                            typ: 'JWT',
                            alg: alg,
                            kid: signingInfo.kid,
                        };
                        publicKey = void 0;
                        keyInfo = void 0;
                        if (didPubKey) {
                            keyInfo = {
                                key: didPubKey.publicKey,
                                kid: didPubKey.id,
                                use: 'sig',
                                kty: globals_1.KTYS[didPubKey.kty],
                                format: didPubKey.format,
                                isPrivate: false,
                            };
                            switch (didPubKey.kty) {
                                case globals_1.KTYS.RSA:
                                    publicKey = JWKUtils_1.RSAKey.fromKey(keyInfo);
                                    break;
                                case globals_1.KTYS.EC: {
                                    if (didPubKey.format === globals_1.KEY_FORMATS.ETHEREUM_ADDRESS) {
                                        keyInfo.key = signingInfo.key;
                                        keyInfo.format = signingInfo.format;
                                        keyInfo.isPrivate = true;
                                    }
                                    publicKey = JWKUtils_1.ECKey.fromKey(keyInfo);
                                    break;
                                }
                                case globals_1.KTYS.OKP:
                                    publicKey = JWKUtils_1.OKP.fromKey(keyInfo);
                                    break;
                            }
                        }
                        else {
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR))];
                        }
                        payload = {
                            iss: 'https://self-issued.me',
                        };
                        payload.did = didSiopUser.getDocument().id;
                        if (requestPayload.client_id)
                            payload.aud = requestPayload.client_id;
                        if (publicKey) {
                            payload.sub_jwk = publicKey.getMinimalJWK();
                            payload.sub = JWKUtils_1.calculateThumbprint(publicKey.getMinimalJWK());
                        }
                        else {
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.PUBLIC_KEY_ERROR))];
                        }
                        if (requestPayload.nonce)
                            payload.nonce = requestPayload.nonce;
                        if (requestPayload.state)
                            payload.state = requestPayload.state;
                        now = Date.now();
                        payload.iat = now;
                        payload.exp = now + expiresIn;
                        payload.vc = vc;
                        unsigned = {
                            header: header,
                            payload: payload,
                        };
                        if (!(parsed.query.grant_type === 'authorization_code')) return [3 /*break*/, 12];
                        idToken = JWT.sign(unsigned, signingInfo);
                        return [4 /*yield*/, this.generateRefreshToken(idToken, crypto)];
                    case 11:
                        refreshToken = _a.sent();
                        return [2 /*return*/, JSON.stringify({ response_type: 'id_token', id_token: idToken, refresh_token: refreshToken })];
                    case 12: return [2 /*return*/, JSON.stringify({ response_type: 'id_token', id_token: JWT.sign(unsigned, signingInfo) })];
                    case 13: return [3 /*break*/, 15];
                    case 14: return [2 /*return*/, ""];
                    case 15: return [3 /*break*/, 17];
                    case 16:
                        err_1 = _a.sent();
                        return [2 /*return*/, Promise.reject(err_1)];
                    case 17: return [2 /*return*/];
                }
            });
        });
    };
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
    DidSiopResponse.validateResponse = function (response, checkParams) {
        return __awaiter(this, void 0, void 0, function () {
            var decodedHeader, decodedPayload, errorResponse, jwkThumbprint, publicKeyInfo, identity, didPubKey, err_2, validity;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        try {
                            errorResponse = ErrorResponse.checkErrorResponse(response);
                            if (errorResponse)
                                return [2 /*return*/, errorResponse];
                            decodedHeader = JSON.parse(base64url_1.default.decode(response.split('.')[0]));
                            decodedPayload = JSON.parse(base64url_1.default.decode(response.split('.')[1]));
                        }
                        catch (err) {
                            return [2 /*return*/, Promise.reject(err)];
                        }
                        if (!((decodedHeader.kid && !decodedHeader.kid.match(/^ *$/)) &&
                            (decodedPayload.iss && !decodedPayload.iss.match(/^ *$/)) &&
                            (decodedPayload.aud && !decodedPayload.aud.match(/^ *$/)) &&
                            (decodedPayload.did && !decodedPayload.did.match(/^ *$/)) &&
                            (decodedPayload.sub && !decodedPayload.sub.match(/^ *$/)) &&
                            (decodedPayload.sub_jwk && !JSON.stringify(decodedPayload.sub_jwk).match(/^ *$/)))) return [3 /*break*/, 5];
                        if (decodedPayload.iss !== 'https://self-issued.me')
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.NON_SIOP_FLOW))];
                        if (decodedPayload.aud !== checkParams.redirect_uri)
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.INCORRECT_AUDIENCE))];
                        if (decodedPayload.nonce && (decodedPayload.nonce !== checkParams.nonce))
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.INCORRECT_NONCE))];
                        if (checkParams.validBefore) {
                            if (decodedPayload.iat) {
                                if (decodedPayload.iat + checkParams.validBefore <= Date.now())
                                    return [2 /*return*/, Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED))];
                            }
                            else {
                                return [2 /*return*/, Promise.reject(new Error(ERRORS.NO_ISSUED_TIME))];
                            }
                        }
                        if (checkParams.isExpirable) {
                            if (decodedPayload.exp) {
                                if (decodedPayload.exp <= Date.now())
                                    return [2 /*return*/, Promise.reject(new Error(ERRORS.JWT_VALIDITY_EXPIRED))];
                            }
                            else {
                                return [2 /*return*/, Promise.reject(new Error(ERRORS.NO_EXPIRATION))];
                            }
                        }
                        jwkThumbprint = JWKUtils_1.calculateThumbprint(decodedPayload.sub_jwk);
                        if (jwkThumbprint !== decodedPayload.sub)
                            return [2 /*return*/, Promise.reject(new Error(ERRORS.INVALID_JWK_THUMBPRINT))];
                        publicKeyInfo = void 0;
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 3, , 4]);
                        identity = new Identity_1.Identity();
                        return [4 /*yield*/, identity.resolve(decodedPayload.did)];
                    case 2:
                        _a.sent();
                        didPubKey = identity.extractAuthenticationKeys().find(function (authKey) {
                            return authKey.id === decodedHeader.kid;
                        });
                        if (didPubKey) {
                            publicKeyInfo = {
                                key: didPubKey.publicKey,
                                kid: didPubKey.id,
                                alg: didPubKey.alg,
                                format: didPubKey.format
                            };
                        }
                        else {
                            throw new Error(ERRORS.PUBLIC_KEY_ERROR);
                        }
                        return [3 /*break*/, 4];
                    case 3:
                        err_2 = _a.sent();
                        return [2 /*return*/, Promise.reject(ERRORS.PUBLIC_KEY_ERROR)];
                    case 4:
                        validity = false;
                        if (publicKeyInfo) {
                            validity = JWT.verify(response, publicKeyInfo);
                        }
                        else {
                            return [2 /*return*/, Promise.reject(ERRORS.PUBLIC_KEY_ERROR)];
                        }
                        if (validity)
                            return [2 /*return*/, {
                                    header: decodedHeader,
                                    payload: decodedPayload,
                                }];
                        return [2 /*return*/, Promise.reject(new Error(ERRORS.INVALID_SIGNATURE_ERROR))];
                    case 5: return [2 /*return*/, Promise.reject(new Error(ERRORS.MALFORMED_JWT_ERROR))];
                }
            });
        });
    };
    /**
     *
     * @param {any} requestPayload - A decoded payload of validated request
     * @param {Crypto} crypto - Used to generate authorization code
     * @returns {Promise<string>} - A promise wich will resolve either to a authorization code
     * or an error response
     * @remarks This method generates authorization code for authentication flow.
     * First it hashes the SIOP request
     * Then an object with fields iat, exp and request is created(hashed request is used as the request);
     * Encrypt the object by a key generated by private key of provider to obtain the authentication code.
     *
     */
    DidSiopResponse.generateAuthorizationCode = function (requestPayload, crypto) {
        return __awaiter(this, void 0, void 0, function () {
            var hashedRequest, authCode, authCodeEncrypted;
            return __generator(this, function (_a) {
                try {
                    hashedRequest = Crypto_1.Crypto.hash(JSON.stringify(requestPayload));
                    authCode = {
                        iat: Date.now(),
                        exp: Date.now() + 1000 * 60 * 10,
                        request: hashedRequest
                    };
                    authCodeEncrypted = crypto.encrypt(JSON.stringify(authCode));
                    return [2 /*return*/, authCodeEncrypted];
                }
                catch (err) {
                    return [2 /*return*/, Promise.reject(new Error(err))];
                }
                return [2 /*return*/];
            });
        });
    };
    /**
     *
     * @param {string} request - DID SIOP request of grant type authorization_code
     * @param {any} requestPayload - A decoded payload of above request
     * @param {Crypto} crypto - Used to generate authorization code
     * @param {Storage} storage - Used to store and check if authorization code is already used
     * @returns {Promise<string>} - A promise which will resolve either to a True statement
     * or an error response
     *
     */
    DidSiopResponse.validateAuthorizationCode = function (request, requestPayload, crypto, storage) {
        return __awaiter(this, void 0, void 0, function () {
            var parsed, authCode, authCodeDecrypted, reqObject, hashedReq, alreadyUsed, err_3;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 7, , 8]);
                        parsed = queryString.parseUrl(request);
                        authCode = parsed.query.code;
                        authCodeDecrypted = crypto.decrypt(authCode);
                        reqObject = JSON.parse(authCodeDecrypted);
                        hashedReq = Crypto_1.Crypto.hash(JSON.stringify(requestPayload));
                        return [4 /*yield*/, storage.getItem(reqObject.iat.toString())];
                    case 1:
                        alreadyUsed = _a.sent();
                        if (!(hashedReq != reqObject.request)) return [3 /*break*/, 2];
                        return [2 /*return*/, Promise.reject(new Error('INVALID REQUEST'))];
                    case 2:
                        if (!(reqObject.exp < Date.now())) return [3 /*break*/, 3];
                        return [2 /*return*/, Promise.reject(new Error('EXPIRED AUTHORIZATION CODE'))];
                    case 3:
                        if (!alreadyUsed) return [3 /*break*/, 4];
                        return [2 /*return*/, Promise.reject(new Error('ALREADY USED CODE'))];
                    case 4: return [4 /*yield*/, storage.setItem(reqObject.iat.toString(), reqObject.request)];
                    case 5:
                        _a.sent();
                        return [2 /*return*/, Promise.resolve('True')];
                    case 6: return [3 /*break*/, 8];
                    case 7:
                        err_3 = _a.sent();
                        if (err_3.message === 'invalid ciphertext size (must be multiple of 16 bytes)') {
                            return [2 /*return*/, Promise.reject(new Error('INVALID AUTH CODE'))];
                        }
                        else {
                            return [2 /*return*/, Promise.reject(err_3)];
                        }
                        return [3 /*break*/, 8];
                    case 8: return [2 /*return*/];
                }
            });
        });
    };
    /**
     *
     * @param {string} id_token - id_token generated by the same provider
     * @param {Crypto} crypto - Used to generate authorization code
     * @returns {Promise<string>} - A promise which will resolve either to a refresh token
     * or an error response
     * @remarks This method generates refresh token for authentication flow.
     *
     */
    DidSiopResponse.generateRefreshToken = function (id_token, crypto) {
        return __awaiter(this, void 0, void 0, function () {
            var hashedIDToken, refreshToken, refreshTokenEncrypted;
            return __generator(this, function (_a) {
                try {
                    hashedIDToken = Crypto_1.Crypto.hash(JSON.stringify(id_token));
                    refreshToken = {
                        iat: Date.now(),
                        exp: Date.now() + 1000 * 60 * 60 * 24 * 30,
                        id_token: hashedIDToken
                    };
                    refreshTokenEncrypted = crypto.encrypt(JSON.stringify(refreshToken));
                    return [2 /*return*/, refreshTokenEncrypted];
                }
                catch (err) {
                    return [2 /*return*/, Promise.reject(new Error(err))];
                }
                return [2 /*return*/];
            });
        });
    };
    /**
     *
     * @param {string} id_token - id_token generated by the same provider
     * @param {string} refresh_token - refresh_token generated by the same provider
     * @param {Crypto} crypto - Used to generate authorization code
     * @returns {Promise<string>} - A promise which will resolve either to true statement
     * or an error response
     * @remarks This method validates refresh_token and id_token.
     *
     */
    DidSiopResponse.validateRefreshToken = function (id_token, refresh_token, crypto) {
        return __awaiter(this, void 0, void 0, function () {
            var hashedIDToken, refreshTokenDecrypted;
            return __generator(this, function (_a) {
                try {
                    hashedIDToken = Crypto_1.Crypto.hash(JSON.stringify(id_token));
                    refreshTokenDecrypted = JSON.parse(crypto.decrypt(refresh_token));
                    if (refreshTokenDecrypted.id_token != hashedIDToken) {
                        return [2 /*return*/, Promise.reject(new Error(ERRORS.TOKEN_MISMATCH))];
                    }
                    if (Date.now() > refreshTokenDecrypted.exp) {
                        return [2 /*return*/, Promise.reject(new Error(ERRORS.EXPIRED_REFRESH_TOKEN))];
                    }
                    return [2 /*return*/, 'true'];
                }
                catch (err) {
                    return [2 /*return*/, Promise.reject(new Error(err))];
                }
                return [2 /*return*/];
            });
        });
    };
    return DidSiopResponse;
}());
exports.DidSiopResponse = DidSiopResponse;
//# sourceMappingURL=Response.js.map