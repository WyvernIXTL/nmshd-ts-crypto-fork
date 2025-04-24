import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoPrivateKey } from "../CryptoPrivateKey";
import { SodiumWrapper } from "../SodiumWrapper";
import { CryptoExchangePrivateKeyHandle } from "../crypto-layer/exchange/CryptoExchangePrivateKeyHandle";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangePublicKey } from "./CryptoExchangePublicKey";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

/**
 * Interface defining the serialized form of CryptoExchangePrivateKey.
 */
export interface ICryptoExchangePrivateKeySerialized extends ISerialized {
    alg: number;
    prv: string;
}

/**
 * Interface defining the structure of CryptoExchangePrivateKey.
 */
export interface ICryptoExchangePrivateKey extends ISerializable {
    algorithm: CryptoExchangeAlgorithm;
    privateKey: ICoreBuffer;
}

/**
 * The original libsodium-based implementation preserved for backward compatibility.
 */
@type("CryptoExchangePrivateKeyWithLibsodium")
export class CryptoExchangePrivateKeyWithLibsodium
    extends CryptoPrivateKey
    implements ICryptoExchangePrivateKey, IClearable
{
    @validate()
    @serialize()
    public override algorithm: CryptoExchangeAlgorithm;

    @validate()
    @serialize()
    public override privateKey: CoreBuffer;

    /**
     * Serializes the private key into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoExchangePrivateKeySerialized}.
     */
    public override toJSON(verbose = true): ICryptoExchangePrivateKeySerialized {
        return {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangePrivateKeyWithLibsodium" : undefined
        };
    }

    /**
     * Clears the sensitive data contained in this private key.
     */
    public clear(): void {
        this.privateKey.clear();
    }

    /**
     * Serializes the key to Base64 encoding.
     *
     * @param verbose - If true, includes type information in the serialized output.
     * @returns Base64 encoded string representation of the key.
     */
    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Derives the public key from the private key using libsodium.
     *
     * @returns A Promise that resolves to a CryptoExchangePublicKey derived from this private key.
     * @throws {@link CryptoError} if key generation fails or algorithm is not supported.
     */
    public async toPublicKey(): Promise<CryptoExchangePublicKey> {
        let publicKey: Uint8Array;
        // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
        switch (this.algorithm) {
            case CryptoExchangeAlgorithm.ECDH_X25519:
                try {
                    publicKey = (await SodiumWrapper.ready()).crypto_scalarmult_base(this.privateKey.buffer);
                } catch (e) {
                    throw new CryptoError(CryptoErrorCode.ExchangeKeyGeneration, `${e}`);
                }
                break;
            default:
                throw new CryptoError(CryptoErrorCode.NotYetImplemented);
        }
        return CryptoExchangePublicKey.from({
            algorithm: this.algorithm,
            publicKey: CoreBuffer.from(publicKey)
        });
    }

    /**
     * Creates an instance of {@link CryptoExchangePrivateKeyWithLibsodium} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangePrivateKey} or an instance.
     * @returns An instance of {@link CryptoExchangePrivateKeyWithLibsodium}.
     */
    public static override from(
        value: CryptoExchangePrivateKeyWithLibsodium | ICryptoExchangePrivateKey
    ): CryptoExchangePrivateKeyWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Pre-processes the input object to normalize key aliases and validate key properties.
     *
     * @param value - The raw input object.
     * @returns The normalized and validated object.
     */
    protected static override preFrom(value: any): any {
        if (value.alg) {
            value = {
                algorithm: value.alg,
                privateKey: CoreBuffer.fromBase64URL(value.prv)
            };
        }
        CryptoExchangeValidation.checkExchangeAlgorithm(value.algorithm);
        CryptoExchangeValidation.checkExchangePrivateKey(value.privateKey, value.algorithm, "privateKey");
        return value;
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangePrivateKeyWithLibsodium} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangePrivateKeySerialized}.
     * @returns An instance of {@link CryptoExchangePrivateKeyWithLibsodium}.
     */
    public static fromJSON(value: ICryptoExchangePrivateKeySerialized): CryptoExchangePrivateKeyWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangePrivateKeyWithLibsodium} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoExchangePrivateKeyWithLibsodium}.
     */
    public static override fromBase64(value: string): CryptoExchangePrivateKeyWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}

/**
 * Extended class that supports handle-based keys if the crypto-layer provider is available.
 * Otherwise, it falls back to the libsodium-based implementation.
 */
@type("CryptoExchangePrivateKey")
export class CryptoExchangePrivateKey extends CryptoExchangePrivateKeyWithLibsodium {
    /**
     * Overrides `toJSON` to produce `@type: "CryptoExchangePrivateKey"`.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation with the extended type.
     */
    public override toJSON(verbose = true): ICryptoExchangePrivateKeySerialized {
        return {
            prv: this.privateKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangePrivateKey" : undefined
        };
    }

    /**
     * Overridden method that checks if a crypto-layer provider is active
     * and if this key is a crypto-layer handle. If so, it delegates to the
     * crypto-layer handle. Otherwise, it calls the parent implementation.
     */
    public override async toPublicKey(): Promise<CryptoExchangePublicKey> {
        if (this instanceof CryptoExchangePrivateKeyHandle) {
            return await this.toPublicKey();
        }
        // Fallback to the libsodium-based method
        return await super.toPublicKey();
    }

    /**
     * Creates a new CryptoExchangePrivateKey from a crypto-layer handle.
     */
    public static fromHandle(handle: CryptoExchangePrivateKeyHandle): CryptoExchangePrivateKey {
        return handle as unknown as CryptoExchangePrivateKey;
    }

    /**
     * Creates an instance of {@link CryptoExchangePrivateKey} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangePrivateKey} or an instance.
     * @returns An instance of {@link CryptoExchangePrivateKey}.
     */
    public static override from(value: CryptoExchangePrivateKey | ICryptoExchangePrivateKey): CryptoExchangePrivateKey {
        if (value instanceof CryptoExchangePrivateKeyHandle) {
            return value as unknown as CryptoExchangePrivateKey;
        }

        const base = super.fromAny(value);
        if (base instanceof CryptoExchangePrivateKey) {
            return base;
        }

        const extended = new CryptoExchangePrivateKey();
        extended.algorithm = base.algorithm;
        extended.privateKey = base.privateKey;
        return extended;
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangePrivateKey} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangePrivateKeySerialized}.
     * @returns An instance of {@link CryptoExchangePrivateKey}.
     */
    public static override fromJSON(value: ICryptoExchangePrivateKeySerialized): CryptoExchangePrivateKey {
        const base = super.fromJSON(value);
        const extended = new CryptoExchangePrivateKey();
        extended.algorithm = base.algorithm;
        extended.privateKey = base.privateKey;
        return extended;
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangePrivateKey} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoExchangePrivateKey}.
     */
    public static override fromBase64(value: string): CryptoExchangePrivateKey {
        const base = super.fromBase64(value);
        const extended = new CryptoExchangePrivateKey();
        extended.algorithm = base.algorithm;
        extended.privateKey = base.privateKey;
        return extended;
    }
}
