import { Cipher, DHExchange, KeyPairSpec } from "@nmshd/rs-crypto-types";
import { CoreBuffer } from "src/CoreBuffer";
import { CryptoError } from "src/CryptoError";
import { CryptoErrorCode } from "src/CryptoErrorCode";
import { CryptoExchangePublicKey } from "src/exchange/CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "src/exchange/CryptoExchangeSecrets";
import { getProviderOrThrow, ProviderIdentifier } from "../CryptoLayerProviders";
import { cryptoEncryptionAlgorithmFromCipher, cryptoExchangeAlgorithmFromAsymmetricKeySpec } from "../CryptoLayerUtils";

export type ExchangeKeyPairSpec = KeyPairSpec & { cipher: Cipher };

// This class did not need to be serializable. `@nmshd/transport` does not use static keys for exchanges.
/**
 * Represents a handle to a private key use for key exchange.
 *
 * This class is not serializable.
 * Creating a static private key is not supported, because of security concerns.
 */
export class CryptoExchangePrivateKeyHandle {
    private readonly dhExchange: DHExchange;

    /** Holds the exchange algorithm being use and what algorithm key handles should have. */
    public readonly spec: ExchangeKeyPairSpec;

    private constructor(dhExchange: DHExchange, spec: ExchangeKeyPairSpec) {
        this.dhExchange = dhExchange;
        this.spec = spec;
    }

    /**
     * Asynchronously creates a {@link CryptoExchangePublicKeyHandle} corresponding to this private key handle.
     * This method leverages the underlying crypto provider to derive the public key from the private key.
     *
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKeyHandle} instance.
     */
    public async toPublicKey(): Promise<CryptoExchangePublicKey> {
        const rawPublicKey = await this.dhExchange.getPublicKey();

        return CryptoExchangePublicKey.from({
            algorithm: cryptoExchangeAlgorithmFromAsymmetricKeySpec(this.spec.asym_spec),
            publicKey: CoreBuffer.from(rawPublicKey)
        });
    }

    public static async new(
        providerIdent: ProviderIdentifier,
        spec: ExchangeKeyPairSpec
    ): Promise<CryptoExchangePrivateKeyHandle> {
        const provider = getProviderOrThrow(providerIdent);
        const dhExchange = await provider.startEphemeralDhExchange(spec);
        return new CryptoExchangePrivateKeyHandle(dhExchange, spec);
    }

    /**
     * Asynchronously derives shared secrets using an existing DHExchange context in the 'requestor' role.
     * Accepts the requestor's DHExchange handle and the templator's PublicKey handle.
     */
    public async deriveRequestor(templatorPublicKeyBytes: Uint8Array): Promise<CryptoExchangeSecrets> {
        try {
            const [rx, tx] = await this.dhExchange.deriveServerSessionKeys(templatorPublicKeyBytes); // Pass bytes here

            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(rx),
                transmissionKey: CoreBuffer.from(tx),
                algorithm: cryptoEncryptionAlgorithmFromCipher(this.spec.cipher)
            });

            return secrets;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
    }

    /**
     * Asynchronously derives shared secrets using an existing DHExchange context in the 'templator' role.
     * Accepts the templator's DHExchange handle and the requestor's PublicKey handle.
     */
    public async deriveTemplator(requestorPublicKeyBytes: Uint8Array): Promise<CryptoExchangeSecrets> {
        try {
            const [rx, tx] = await this.dhExchange.deriveClientSessionKeys(requestorPublicKeyBytes); // Pass bytes here

            const secrets = CryptoExchangeSecrets.from({
                receivingKey: CoreBuffer.from(rx),
                transmissionKey: CoreBuffer.from(tx),
                algorithm: cryptoEncryptionAlgorithmFromCipher(this.spec.cipher)
            });

            return secrets;
        } catch (e) {
            throw new CryptoError(CryptoErrorCode.ExchangeKeyDerivation, `${e}`);
        }
    }
}
