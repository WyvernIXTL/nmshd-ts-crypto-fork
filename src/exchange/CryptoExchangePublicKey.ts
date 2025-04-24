import { ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable } from "../CoreBuffer";
import { CryptoPublicKey } from "../CryptoPublicKey";
import { CryptoExchangeAlgorithm } from "./CryptoExchange";
import { CryptoExchangeValidation } from "./CryptoExchangeValidation";

/**
 * Interface defining the serialized form of CryptoExchangePublicKey.
 */
export interface ICryptoExchangePublicKeySerialized extends ISerialized {
    alg: number;
    pub: string;
}

/**
 * Interface defining the structure of CryptoExchangePublicKey.
 */
export interface ICryptoExchangePublicKey {
    algorithm: CryptoExchangeAlgorithm;
    publicKey: CoreBuffer;
}

/**
 * The original libsodium-based implementation preserved for backward compatibility.
 */
@type("CryptoExchangePublicKeyWithLibsodium")
export class CryptoExchangePublicKeyWithLibsodium
    extends CryptoPublicKey
    implements ICryptoExchangePublicKey, IClearable
{
    @validate()
    @serialize()
    public override algorithm: CryptoExchangeAlgorithm;

    @validate()
    @serialize()
    public override publicKey: CoreBuffer;

    /**
     * Serializes the public key into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoExchangePublicKeySerialized}.
     */
    public override toJSON(verbose = true): ICryptoExchangePublicKeySerialized {
        return {
            "@type": verbose ? "CryptoExchangePublicKeyWithLibsodium" : undefined,
            pub: this.publicKey.toBase64URL(),
            alg: this.algorithm
        };
    }

    /**
     * Clears the sensitive data contained in this public key.
     */
    public clear(): void {
        this.publicKey.clear();
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
                publicKey: value.pub
            };
        }

        CryptoExchangeValidation.checkExchangeAlgorithm(value.algorithm);
        CryptoExchangeValidation.checkExchangePublicKey(value.publicKey, value.algorithm);

        return value;
    }

    /**
     * Creates an instance of {@link CryptoExchangePublicKeyWithLibsodium} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangePublicKey} or an instance.
     * @returns An instance of {@link CryptoExchangePublicKeyWithLibsodium}.
     */
    public static override from(
        value: CryptoExchangePublicKeyWithLibsodium | ICryptoExchangePublicKey
    ): CryptoExchangePublicKeyWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangePublicKeyWithLibsodium} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangePublicKeySerialized}.
     * @returns An instance of {@link CryptoExchangePublicKeyWithLibsodium}.
     */
    public static fromJSON(value: ICryptoExchangePublicKeySerialized): CryptoExchangePublicKeyWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangePublicKeyWithLibsodium} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoExchangePublicKeyWithLibsodium}.
     */
    public static override fromBase64(value: string): CryptoExchangePublicKeyWithLibsodium {
        return this.deserialize(CoreBuffer.base64_utf8(value));
    }
}

/**
 * Extended class that supports handle-based keys if the crypto-layer provider is available.
 * Otherwise, it falls back to the libsodium-based implementation.
 */
@type("CryptoExchangePublicKey")
export class CryptoExchangePublicKey extends CryptoExchangePublicKeyWithLibsodium {
    /**
     * Overrides `toJSON` to produce `@type: "CryptoExchangePublicKey"`.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation with the extended type.
     */
    public override toJSON(verbose = true): ICryptoExchangePublicKeySerialized {
        return {
            "@type": verbose ? "CryptoExchangePublicKey" : undefined,
            pub: this.publicKey.toBase64URL(),
            alg: this.algorithm
        };
    }

    /**
     * Creates an instance of {@link CryptoExchangePublicKey} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangePublicKey} or an instance.
     * @returns An instance of {@link CryptoExchangePublicKey}.
     */
    public static override from(value: CryptoExchangePublicKey | ICryptoExchangePublicKey): CryptoExchangePublicKey {
        const base = super.fromAny(value);
        if (base instanceof CryptoExchangePublicKey) {
            return base;
        }

        const extended = new CryptoExchangePublicKey();
        extended.algorithm = base.algorithm;
        extended.publicKey = base.publicKey;
        return extended;
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangePublicKey} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangePublicKeySerialized}.
     * @returns An instance of {@link CryptoExchangePublicKey}.
     */
    public static override fromJSON(value: ICryptoExchangePublicKeySerialized): CryptoExchangePublicKey {
        const base = super.fromJSON(value);
        const extended = new CryptoExchangePublicKey();
        extended.algorithm = base.algorithm;
        extended.publicKey = base.publicKey;
        return extended;
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangePublicKey} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns An instance of {@link CryptoExchangePublicKey}.
     */
    public static override fromBase64(value: string): CryptoExchangePublicKey {
        const base = super.fromBase64(value);
        const extended = new CryptoExchangePublicKey();
        extended.algorithm = base.algorithm;
        extended.publicKey = base.publicKey;
        return extended;
    }
}
