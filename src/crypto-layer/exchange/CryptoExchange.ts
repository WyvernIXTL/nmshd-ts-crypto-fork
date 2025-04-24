import { CryptoExchangePublicKey } from "src/exchange/CryptoExchangePublicKey";
import { CryptoExchangeSecrets } from "../../exchange/CryptoExchangeSecrets";
import { ProviderIdentifier } from "../CryptoLayerProviders";
import { CryptoExchangeKeypairHandle } from "./CryptoExchangeKeypairHandle";
import { CryptoExchangePrivateKeyHandle, ExchangeKeyPairSpec } from "./CryptoExchangePrivateKeyHandle";

/**
 * Provides cryptographic key exchange functionalities using the crypto layer.
 * This class is designed to replace the libsodium-based implementation, leveraging
 * the Rust-based crypto layer for enhanced security and performance.
 */
export class CryptoExchangeWithCryptoLayer {
    /**
     * Asynchronously converts a private key handle for key exchange into its corresponding public key handle.
     *
     * @param privateKey - The {@link CryptoExchangePrivateKeyHandle} to convert.
     * @returns A Promise that resolves to a {@link CryptoExchangePublicKey}.
     */
    public static async privateKeyToPublicKey(
        privateKey: CryptoExchangePrivateKeyHandle
    ): Promise<CryptoExchangePublicKey> {
        return await privateKey.toPublicKey();
    }

    /**
     * Asynchronously generates a key pair for cryptographic key exchange using the crypto layer.
     *
     * @param providerIdent - Identifier for the crypto provider to be used for key generation.
     * @param spec - Specification for the key pair to be generated, including algorithm and security parameters.
     * @returns A Promise that resolves to a {@link CryptoExchangeKeypairHandle} containing the generated key pair handles.
     */
    public static async generateKeypair(
        providerIdent: ProviderIdentifier,
        spec: ExchangeKeyPairSpec
    ): Promise<CryptoExchangeKeypairHandle> {
        const privateKey = await CryptoExchangePrivateKeyHandle.new(providerIdent, spec);
        const publicKey = await privateKey.toPublicKey();
        return CryptoExchangeKeypairHandle.fromPublicAndPrivateKeys(publicKey, privateKey);
    }

    /**
     * Asynchronously derives shared secrets using an existing DHExchange context in the 'requestor' role.
     * Accepts the requestor's DHExchange handle and the templator's PublicKey handle.
     */
    public static async deriveRequestor(
        requestor: CryptoExchangePrivateKeyHandle,
        templator: CryptoExchangePublicKey
    ): Promise<CryptoExchangeSecrets> {
        return await requestor.deriveRequestor(templator.publicKey.buffer);
    }

    /**
     * Asynchronously derives shared secrets using an existing DHExchange context in the 'templator' role.
     * Accepts the templator's DHExchange handle and the requestor's PublicKey handle.
     */
    public static async deriveTemplator(
        templator: CryptoExchangePrivateKeyHandle,
        requestor: CryptoExchangePublicKey
    ): Promise<CryptoExchangeSecrets> {
        return await templator.deriveTemplator(requestor.publicKey.buffer);
    }
}
