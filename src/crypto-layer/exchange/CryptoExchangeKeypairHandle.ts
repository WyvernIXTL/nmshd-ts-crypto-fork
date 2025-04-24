import { CryptoExchangePublicKey } from "src/exchange/CryptoExchangePublicKey";
import { CryptoExchangePrivateKeyHandle } from "./CryptoExchangePrivateKeyHandle";

/**
 * Represents a key pair for cryptographic key exchange operations, managed by the crypto layer.
 * This class holds handles to both the public and private keys, allowing for operations
 * that require both parts of the key pair without exposing the raw key material directly in the application.
 * It extends {@link CryptoSerializableAsync} to support asynchronous serialization and deserialization.
 */
export class CryptoExchangeKeypairHandle {
    /**
     * The public key handle of the key pair.
     */
    public publicKey: CryptoExchangePublicKey;

    /**
     * The private key handle of the key pair.
     */
    public privateKey: CryptoExchangePrivateKeyHandle;

    /**
     * Creates a new {@link CryptoExchangeKeypairHandle} using the provided public and private keys.
     *
     * @param publicKey - The public key handle to associate with the keypair.
     * @param privateKey - The private key handle to associate with the keypair.
     * @returns A new instance of CryptoExchangeKeypairHandle with the specified keys.
     */
    public static fromPublicAndPrivateKeys(
        publicKey: CryptoExchangePublicKey,
        privateKey: CryptoExchangePrivateKeyHandle
    ): CryptoExchangeKeypairHandle {
        const keyPair = new this();
        keyPair.privateKey = privateKey;
        keyPair.publicKey = publicKey;
        return keyPair;
    }
}
