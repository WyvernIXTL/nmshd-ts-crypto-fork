import { ExchangeKeyPairSpec } from "src/crypto-layer";
import { CoreBuffer } from "../CoreBuffer";
import { ProviderIdentifier } from "../crypto-layer/CryptoLayerProviders";
import { CryptoExchangeWithCryptoLayer } from "../crypto-layer/exchange/CryptoExchange";
import { CryptoExchangeKeypairHandle } from "../crypto-layer/exchange/CryptoExchangeKeypairHandle";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangeKeypair } from "./CryptoExchangeKeypair";
import { CryptoExchangePrivateKey } from "./CryptoExchangePrivateKey";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "./CryptoExchangeSecrets";

/**
 * The key exchange algorithm to use.
 */
export const enum CryptoExchangeAlgorithm {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P256 = 1,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_P521 = 2,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ECDH_X25519 = 3
}

export class CryptoExchangeWithLibsodium {
    public static async generateKeypair(
        algorithm: CryptoExchangeAlgorithm = CryptoExchangeAlgorithm.ECDH_X25519
    ): Promise<CryptoExchangeKeypair> {
        let privateKeyBuffer: Uint8Array;
        let publicKeyBuffer: Uint8Array;

        switch (algorithm as number) {
            case CryptoExchangeAlgorithm.ECDH_X25519:
                let pair;
                try {
                    pair = (await SodiumWrapper.ready()).crypto_kx_keypair();
                } catch (e: any) {
                    throw new CryptoError(CryptoErrorCode.ExchangeKeyGeneration, `${e}`);
                }
                privateKeyBuffer = pair.privateKey;
                publicKeyBuffer = pair.publicKey;
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }

        const privateKey = CryptoExchangePrivateKey.from({
            algorithm,
            privateKey: CoreBuffer.from(privateKeyBuffer)
        });
        const publicKey = CryptoExchangePublicKey.from({
            algorithm,
            publicKey: CoreBuffer.from(publicKeyBuffer)
        });
        return CryptoExchangeKeypair.from({ publicKey, privateKey });
    }

    public static async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair,
        templatorPublicKey: CryptoExchangePublicKey,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        let sharedKey;
        try {
            sharedKey = (await SodiumWrapper.ready()).crypto_kx_server_session_keys(
                requestorKeypair.publicKey.publicKey.buffer,
                requestorKeypair.privateKey.privateKey.buffer,
                templatorPublicKey.publicKey.buffer
            );
        } catch (e: any) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
        return CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
    }

    public static async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair,
        requestorPublicKey: CryptoExchangePublicKey,
        algorithm: CryptoEncryptionAlgorithm = CryptoEncryptionAlgorithm.XCHACHA20_POLY1305
    ): Promise<CryptoExchangeSecrets> {
        let sharedKey;
        try {
            sharedKey = (await SodiumWrapper.ready()).crypto_kx_client_session_keys(
                templatorKeypair.publicKey.publicKey.buffer,
                templatorKeypair.privateKey.privateKey.buffer,
                requestorPublicKey.publicKey.buffer
            );
        } catch (e: any) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
        return CryptoExchangeSecrets.from({
            receivingKey: CoreBuffer.from(sharedKey.sharedRx),
            transmissionKey: CoreBuffer.from(sharedKey.sharedTx),
            algorithm: algorithm
        });
    }
}

/**
 * Extended CryptoExchange class.
 *
 * The methods accept a keypair whose private key may be either a traditional (libsodium-generated)
 * key (an instance of CryptoExchangePrivateKey) or a crypto-layer–backed key (an instance of
 * CryptoExchangeKeypairHandle). Similarly, the public key parameters may be either type.
 * Based on the key type (as determined by a helper property such as isCryptoLayerKey),
 * the corresponding implementation is called.
 */
export class CryptoExchange extends CryptoExchangeWithLibsodium {
    public static async generateKeypairHandle(
        providerIdent: ProviderIdentifier,
        spec: ExchangeKeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        return await CryptoExchangeWithCryptoLayer.generateKeypair(providerIdent, spec);
    }

    /**
     * Derives session keys (requestor/server role).
     *
     * Dispatches to either libsodium or crypto-layer based on argument types:
     * - Libsodium: If `requestorKeypair` is {@link CryptoExchangeKeypair} and `templatorPublicKey` is {@link CryptoExchangePublicKey}.
     * - Crypto-Layer: If `requestorKeypair` is {@link CryptoExchangeKeypairHandle} and `templatorPublicKey` is {@link CryptoExchangePublicKey}. Requires initialized provider.
     *
     * @param requestorKeypair The keypair/handle of the sending side ({@link CryptoExchangeKeypair} or {@link CryptoExchangeKeypairHandle}).
     * @param templatorPublicKey The public key of the receiving side ({@link CryptoExchangePublicKey}).
     * @param algorithm The {@link CryptoEncryptionAlgorithm} to tag the derived secrets with.
     *                  Defaults to `XCHACHA20_POLY1305` for libsodium.
     *                  **This function throws if an algorithm is supplied for use with {@link CryptoExchangeKeypairHandle}!**
     *                  The algorithm for {@link CryptoExchangeKeypairHandle} needs to be set at creation.
     * @returns A Promise resolving into a {@link CryptoExchangeSecrets} object.
     * @throws {CryptoError} If argument types are incompatible, provider unavailable, or derivation fails.
     */
    public static override async deriveRequestor(
        requestorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        templatorPublicKey: CryptoExchangePublicKey,
        algorithm?: CryptoEncryptionAlgorithm
    ): Promise<CryptoExchangeSecrets> {
        if (requestorKeypair instanceof CryptoExchangeKeypairHandle) {
            if (algorithm) {
                throw new CryptoError(
                    CryptoErrorCode.WrongParameters,
                    "The algorithm used for the finished keys is set during the creation of CryptoExchangeKeypairHandle."
                );
            }

            return await CryptoExchangeWithCryptoLayer.deriveRequestor(requestorKeypair.privateKey, templatorPublicKey);
        }

        const effectiveAlgorithm = algorithm ?? CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
        return await super.deriveRequestor(requestorKeypair, templatorPublicKey, effectiveAlgorithm);
    }

    /**
     * Derives session keys (templator/client role).
     *
     * Dispatches to either libsodium or crypto-layer based on argument types:
     * - Libsodium: If `templatorKeypair` is {@link CryptoExchangeKeypair} and `requestorPublicKey` is {@link CryptoExchangePublicKey}.
     * - Crypto-Layer: If `templatorKeypair` is {@link CryptoExchangeKeypairHandle} and `requestorPublicKey` is {@link CryptoExchangePublicKey}. Requires initialized provider.
     *
     * @param templatorKeypair The keypair/handle of the receiving side ({@link CryptoExchangeKeypair} or {@link CryptoExchangeKeypairHandle}).
     * @param requestorPublicKey The public key of the sending side ({@link CryptoExchangePublicKey}).
     * @param algorithm The {@link CryptoEncryptionAlgorithm} to tag the derived secrets with.
     *                  Defaults to `XCHACHA20_POLY1305` for libsodium.
     *                  **This function throws if an algorithm is supplied for use with {@link CryptoExchangeKeypairHandle}!**
     *                  The algorithm for {@link CryptoExchangeKeypairHandle} needs to be set at creation.
     * @returns A Promise resolving into a {@link CryptoExchangeSecrets} object.
     * @throws {CryptoError} If argument types are incompatible, provider unavailable, or derivation fails.
     */
    public static override async deriveTemplator(
        templatorKeypair: CryptoExchangeKeypair | CryptoExchangeKeypairHandle,
        requestorPublicKey: CryptoExchangePublicKey,
        algorithm?: CryptoEncryptionAlgorithm
    ): Promise<CryptoExchangeSecrets> {
        if (templatorKeypair instanceof CryptoExchangeKeypairHandle) {
            if (algorithm) {
                throw new CryptoError(
                    CryptoErrorCode.WrongParameters,
                    "The algorithm used for the finished keys is set during the creation of CryptoExchangeKeypairHandle."
                );
            }

            return await CryptoExchangeWithCryptoLayer.deriveTemplator(templatorKeypair.privateKey, requestorPublicKey);
        }
        const effectiveAlgorithm = algorithm ?? CryptoEncryptionAlgorithm.XCHACHA20_POLY1305;
        return await super.deriveTemplator(templatorKeypair, requestorPublicKey, effectiveAlgorithm);
    }
}
