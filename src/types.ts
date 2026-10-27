// Copied from capsl's frontend/src/backend.ts by scripts/publish-crypto.py.
// Only the types the envelope uses; do not edit here.

export interface CryptoFactor {
    kind: string;
    params: Uint8Array;
}

export interface CryptoLayer {
    alg: string;
    payload: Uint8Array;
    innerCommit: Uint8Array;
}

export interface CapsuleCrypto {
    version: number;
    factors: CryptoFactor[];
    layers: CryptoLayer[];
    headerMac: Uint8Array;
    ciphertext: Uint8Array;
    commit: Uint8Array;
    timeIdentity?: Uint8Array;
    ext: Array<[string, Uint8Array]>;
}

export interface AttachmentMetadata {
    id: string;
    filename: string;
    contentType: string;
    size: bigint;
}
