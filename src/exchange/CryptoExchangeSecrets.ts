import { ISerializable, ISerialized, serialize, type, validate } from "@js-soft/ts-serval";
import { CoreBuffer, IClearable, ICoreBuffer } from "../CoreBuffer";
import { CryptoSerializable } from "../CryptoSerializable";
import { CryptoEncryptionAlgorithm } from "../encryption/CryptoEncryption";

/**
 * Interface defining the serialized form of CryptoExchangeSecrets.
 */
export interface ICryptoExchangeSecretsSerialized extends ISerialized {
    alg: CryptoEncryptionAlgorithm;
    rx: string;
    tx: string;
}

/**
 * Interface defining the structure of CryptoExchangeSecrets.
 */
export interface ICryptoExchangeSecrets extends ISerializable {
    algorithm: CryptoEncryptionAlgorithm;
    receivingKey: ICoreBuffer;
    transmissionKey: ICoreBuffer;
}

/**
 * The original libsodium-based implementation preserved for backward compatibility.
 */
@type("CryptoExchangeSecretsWithLibsodium")
export class CryptoExchangeSecretsWithLibsodium
    extends CryptoSerializable
    implements ICryptoExchangeSecrets, IClearable
{
    @validate()
    @serialize()
    public algorithm: CryptoEncryptionAlgorithm;

    @validate()
    @serialize()
    public receivingKey: CoreBuffer;

    @validate()
    @serialize()
    public transmissionKey: CoreBuffer;

    /**
     * Serializes the exchange secrets into its JSON representation.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation conforming to {@link ICryptoExchangeSecretsSerialized}.
     */
    public override toJSON(verbose = true): ICryptoExchangeSecretsSerialized {
        return {
            rx: this.receivingKey.toBase64URL(),
            tx: this.transmissionKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangeSecretsWithLibsodium" : undefined
        };
    }

    /**
     * Clears the sensitive data contained in this exchange secrets.
     */
    public clear(): void {
        this.receivingKey.clear();
        this.transmissionKey.clear();
    }

    /**
     * Serializes the secrets to a JSON string.
     *
     * @param verbose - If true, includes type information in the serialized output.
     * @returns The JSON string representation.
     */
    public override serialize(verbose = true): string {
        return JSON.stringify(this.toJSON(verbose));
    }

    /**
     * Serializes the secrets to Base64 encoding.
     *
     * @param verbose - If true, includes type information in the serialized output.
     * @returns Base64 encoded string representation.
     */
    public override toBase64(verbose = true): string {
        return CoreBuffer.utf8_base64(this.serialize(verbose));
    }

    /**
     * Creates an instance of {@link CryptoExchangeSecretsWithLibsodium} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangeSecrets} or an instance.
     * @returns An instance of {@link CryptoExchangeSecretsWithLibsodium}.
     */
    public static from(
        value: CryptoExchangeSecretsWithLibsodium | ICryptoExchangeSecrets
    ): CryptoExchangeSecretsWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Pre-processes the input object to normalize key aliases.
     *
     * @param value - The raw input object.
     * @returns The normalized object.
     */
    protected static override preFrom(value: any): any {
        if (value.rx) {
            value = {
                algorithm: value.alg,
                receivingKey: value.rx,
                transmissionKey: value.tx
            };
        }
        return value;
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangeSecretsWithLibsodium} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangeSecretsSerialized}.
     * @returns An instance of {@link CryptoExchangeSecretsWithLibsodium}.
     */
    public static fromJSON(value: ICryptoExchangeSecretsSerialized): CryptoExchangeSecretsWithLibsodium {
        return this.fromAny(value);
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangeSecretsWithLibsodium} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns A Promise that resolves to an instance of {@link CryptoExchangeSecretsWithLibsodium}.
     */
    public static fromBase64(value: string): Promise<CryptoExchangeSecretsWithLibsodium> {
        return Promise.resolve(this.deserialize(CoreBuffer.base64_utf8(value)));
    }
}

/**
 * Extended class that supports handle-based keys if the crypto-layer provider is available.
 * Otherwise, it falls back to the libsodium-based implementation.
 */
@type("CryptoExchangeSecrets")
export class CryptoExchangeSecrets extends CryptoExchangeSecretsWithLibsodium {
    /**
     * Overrides `toJSON` to produce `@type: "CryptoExchangeSecrets"`.
     *
     * @param verbose - If true, includes the "@type" property in the output.
     * @returns The serialized representation with the extended type.
     */
    public override toJSON(verbose = true): ICryptoExchangeSecretsSerialized {
        return {
            rx: this.receivingKey.toBase64URL(),
            tx: this.transmissionKey.toBase64URL(),
            alg: this.algorithm,
            "@type": verbose ? "CryptoExchangeSecrets" : undefined
        };
    }

    /**
     * Creates an instance of {@link CryptoExchangeSecrets} from a plain object or instance.
     *
     * @param value - An object conforming to {@link ICryptoExchangeSecrets} or an instance.
     * @returns An instance of {@link CryptoExchangeSecrets}.
     */
    public static override from(value: CryptoExchangeSecrets | ICryptoExchangeSecrets): CryptoExchangeSecrets {
        const base = super.fromAny(value);
        if (base instanceof CryptoExchangeSecrets) {
            return base;
        }

        const extended = new CryptoExchangeSecrets();
        extended.algorithm = base.algorithm;
        extended.receivingKey = base.receivingKey;
        extended.transmissionKey = base.transmissionKey;
        return extended;
    }

    /**
     * Deserializes a JSON object into a {@link CryptoExchangeSecrets} instance.
     *
     * @param value - The JSON object conforming to {@link ICryptoExchangeSecretsSerialized}.
     * @returns An instance of {@link CryptoExchangeSecrets}.
     */
    public static override fromJSON(value: ICryptoExchangeSecretsSerialized): CryptoExchangeSecrets {
        const base = super.fromJSON(value);
        const extended = new CryptoExchangeSecrets();
        extended.algorithm = base.algorithm;
        extended.receivingKey = base.receivingKey;
        extended.transmissionKey = base.transmissionKey;
        return extended;
    }

    /**
     * Deserializes a Base64 encoded string into a {@link CryptoExchangeSecrets} instance.
     *
     * @param value - The Base64 encoded string.
     * @returns A Promise that resolves to an instance of {@link CryptoExchangeSecrets}.
     */
    public static override fromBase64(value: string): Promise<CryptoExchangeSecrets> {
        return super.fromBase64(value).then((base) => {
            const extended = new CryptoExchangeSecrets();
            extended.algorithm = base.algorithm;
            extended.receivingKey = base.receivingKey;
            extended.transmissionKey = base.transmissionKey;
            return extended;
        });
    }
}
