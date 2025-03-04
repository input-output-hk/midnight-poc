import SDK from "@hyperledger/identus-edge-agent-sdk";
import { type Logger } from 'pino';

export type SupportedAlgorithm = 'ES256K' | 'EdDSA';

export interface JWTVerificationResult {
    isValid: boolean;
    payload?: any;
    error?: string;
}


export function isSecp256k1Key(key: SDK.Domain.PublicKeyJWK): key is SDK.Domain.PublicKeyJWK & { y: string } {
    return key.kty === "EC" &&
        key.crv?.toLowerCase().includes('secp256k1') &&
        typeof key.y === 'string';
}


export function isEd25519Key(key: SDK.Domain.PublicKeyJWK): boolean {
    return key.kty === "OKP" && key.crv === "Ed25519";
}

function base64UrlDecode(str: string): Buffer {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    return Buffer.from(base64 + padding, 'base64');
}

function createSecp256k1PublicKey(publicKeyJwk: SDK.Domain.PublicKeyJWK): SDK.Secp256k1PublicKey {
    if (!isSecp256k1Key(publicKeyJwk)) {
        throw new Error('Invalid key type: Expected secp256k1 key');
    }

    const xBytes = base64UrlDecode(publicKeyJwk.x);
    const yBytes = base64UrlDecode(publicKeyJwk.y);

    return SDK.Secp256k1PublicKey.secp256k1FromByteCoordinates(xBytes, yBytes);
}

function createEd25519PublicKey(publicKeyJwk: SDK.Domain.PublicKeyJWK): SDK.Ed25519PublicKey {
    if (!isEd25519Key(publicKeyJwk)) {
        throw new Error('Invalid key type: Expected Ed25519 key');
    }

    const xBytes = base64UrlDecode(publicKeyJwk.x);

    return SDK.Ed25519PublicKey.from.Buffer(xBytes);
}



export function parseJWT(token: string): { header: any; payload: any; signature: Buffer } {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    return {
        header: JSON.parse(base64UrlDecode(parts[0]).toString()),
        payload: JSON.parse(base64UrlDecode(parts[1]).toString()),
        signature: base64UrlDecode(parts[2])
    };
}

/**
 * Verifies a JWT using a public key in JWK format
 */
export async function verifyJWT(
    jwt: string,
    publicKeyJwk: SDK.Domain.PublicKeyJWK,
    logger?: Logger
): Promise<JWTVerificationResult> {
    try {
        logger?.info('Starting JWT verification');
        logger?.info('Public Key JWK:', publicKeyJwk);

        const { header, payload, signature } = parseJWT(jwt);

        if (isEd25519Key(publicKeyJwk) && header.alg !== 'EdDSA') {
            throw new Error('Algorithm mismatch: Expected EdDSA');
        }
        if (isSecp256k1Key(publicKeyJwk) && header.alg !== 'ES256K') {
            throw new Error('Algorithm mismatch: Expected ES256K');
        }
        // TODO: Implement expiration validation when you dont have hardcoded jwt
        // if (!validateJWTExpiration(payload)) {
        //     throw new Error('JWT has expired or is not yet valid');
        // }

        const message = Buffer.from(jwt.split('.').slice(0, 2).join('.'));

        let isSignatureValid = false;
        if (isSecp256k1Key(publicKeyJwk)) {
            const publicKey = createSecp256k1PublicKey(publicKeyJwk);
            isSignatureValid = publicKey.verify(message, signature);
        } else if (isEd25519Key(publicKeyJwk)) {
            const publicKey = createEd25519PublicKey(publicKeyJwk);
            isSignatureValid = publicKey.verify(message, signature);
        } else {
            throw new Error('Unsupported key type');
        }

        if (!isSignatureValid) {
            throw new Error('Invalid signature');
        }

        logger?.debug('JWT verification successful');
        return {
            isValid: true,
            payload
        };

    } catch (error) {
        logger?.error('JWT verification failed:', error);
        return {
            isValid: false,
            error: error instanceof Error ? error.message : 'Unknown error during verification'
        };
    }
}


export function validateJWTExpiration(payload: any): boolean {
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && now >= payload.exp) {
        return false;
    }

    if (payload.nbf && now < payload.nbf) {
        return false;
    }

    return true;
}

