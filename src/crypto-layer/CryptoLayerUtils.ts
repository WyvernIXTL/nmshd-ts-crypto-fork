/* eslint-disable @typescript-eslint/naming-convention */
import { AsymmetricKeySpec, Cipher, CryptoHash, KeyPairHandle, KeyPairSpec, Provider } from "@nmshd/rs-crypto-types";
import { defaults } from "lodash";
import { CryptoEncryptionAlgorithm } from "src/encryption/CryptoEncryption";
import { CoreBuffer } from "../CoreBuffer";
import { CryptoError } from "../CryptoError";
import { CryptoErrorCode } from "../CryptoErrorCode";
import { CryptoExchangeAlgorithm } from "../exchange/CryptoExchange";
import { CryptoHashAlgorithm } from "../hash/CryptoHash";
import { CryptoSignatureAlgorithm } from "../signature/CryptoSignatureAlgorithm";
import { getProviderOrThrow, ProviderIdentifier } from "./CryptoLayerProviders";

export const DEFAULT_KEY_PAIR_SPEC: KeyPairSpec = {
    asym_spec: "P256",
    cipher: "AesGcm256",
    signing_hash: "Sha2_512",
    ephemeral: false,
    non_exportable: false
};

export function asymSpecFromCryptoAlgorithm(
    algorithm: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm
): AsymmetricKeySpec {
    switch (algorithm) {
        case CryptoExchangeAlgorithm.ECDH_P256:
            return "P256";
        case CryptoExchangeAlgorithm.ECDH_P521:
            return "P521";
        case CryptoExchangeAlgorithm.ECDH_X25519:
            return "Curve25519";
        case CryptoSignatureAlgorithm.ECDSA_P256:
            return "P256";
        case CryptoSignatureAlgorithm.ECDSA_P521:
            return "P521";
        case CryptoSignatureAlgorithm.ECDSA_ED25519:
            return "Curve25519";
    }
}

export function cryptoExchangeAlgorithmFromAsymmetricKeySpec(asymSpec: AsymmetricKeySpec): CryptoExchangeAlgorithm {
    // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
    switch (asymSpec) {
        case "P256":
            return CryptoExchangeAlgorithm.ECDH_P256;
        case "P521":
            return CryptoExchangeAlgorithm.ECDH_P521;
        case "Curve25519":
            return CryptoExchangeAlgorithm.ECDH_X25519;
        default:
            throw new CryptoError(
                CryptoErrorCode.ExchangeWrongAlgorithm,
                `Unsupported asymmetric key spec: ${asymSpec}`
            );
    }
}

export function cryptoHashAlgorithmFromAsymSpec(hashFunction: CryptoHash): CryptoHashAlgorithm {
    // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
    switch (hashFunction) {
        case "Sha2_256":
            return CryptoHashAlgorithm.SHA256;
        case "Sha2_512":
            return CryptoHashAlgorithm.SHA512;
        case "Blake2b":
            return CryptoHashAlgorithm.BLAKE2B;
        default:
            throw new CryptoError(
                CryptoErrorCode.WrongHashAlgorithm,
                `Hash function ${hashFunction} is not supported by ts crypto.`
            );
    }
}

export function cryptoHashFromCryptoHashAlgorithm(algorithm: CryptoHashAlgorithm): CryptoHash {
    switch (algorithm) {
        case CryptoHashAlgorithm.SHA256:
            return "Sha2_256";
        case CryptoHashAlgorithm.SHA512:
            return "Sha2_512";
        case CryptoHashAlgorithm.BLAKE2B:
            return "Blake2b";
    }
}

export function cryptoEncryptionAlgorithmFromCipher(cipher: Cipher): CryptoEncryptionAlgorithm {
    // eslint-disable-next-line @typescript-eslint/switch-exhaustiveness-check
    switch (cipher) {
        case "AesGcm128":
            return CryptoEncryptionAlgorithm.AES128_GCM;
        case "AesGcm256":
            return CryptoEncryptionAlgorithm.AES256_GCM;
        default:
            throw new CryptoError(
                CryptoErrorCode.EncryptionWrongCipher,
                `Cipher ${cipher} is not supported by ts crypto.`
            );
    }
}

export class CryptoLayerUtils {
    /**
     * Returns a provider and a key pair handle from default key spec and a raw private key.
     *
     * @param providerIdent An identifier of an initialized provider.
     * @param privateKeyBuffer The raw private key.
     * @param specOverride Override default key pair spec.
     * @returns Tuple with provider and handle to key pair.
     *
     * @throws `CryptoErrorCode.WrongParameters` if providerIdent does not match any initialized providers or if provider cannot import key pair.
     */
    public static async providerAndKeyPairFromPrivateBuffer(
        providerIdent: ProviderIdentifier,
        privateKeyBuffer: CoreBuffer,
        specOverride: Partial<KeyPairSpec>
    ): Promise<[Provider, KeyPairHandle]> {
        const provider = getProviderOrThrow(providerIdent);
        const spec = defaults(specOverride, DEFAULT_KEY_PAIR_SPEC);
        const keyPair = await provider.importKeyPair(spec, new Uint8Array(0), privateKeyBuffer.buffer);
        return [provider, keyPair];
    }

    public static async providerAndKeyPairFromPrivateBufferWithAlgorithm(
        providerIdent: ProviderIdentifier,
        privateKeyBuffer: CoreBuffer,
        asymmetricAlgorithm?: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        hashAlgorithm?: CryptoHashAlgorithm
    ): Promise<[Provider, KeyPairHandle]> {
        const override: Partial<KeyPairSpec> = {
            asym_spec: asymmetricAlgorithm ? asymSpecFromCryptoAlgorithm(asymmetricAlgorithm) : undefined,
            signing_hash: hashAlgorithm ? cryptoHashFromCryptoHashAlgorithm(hashAlgorithm) : undefined
        };
        return await this.providerAndKeyPairFromPrivateBuffer(providerIdent, privateKeyBuffer, override);
    }

    /**
     * Returns a provider and a key pair handle from default key spec and a raw public key.
     *
     * @param providerIdent An identifier of an initialized provider.
     * @param privateKeyBuffer The raw public key.
     * @param specOverride Override default key pair spec.
     * @returns Tuple with provider and handle to key pair.
     *
     * @throws `CryptoErrorCode.WrongParameters` if providerIdent does not match any initialized providers or if provider cannot import key pair.
     */
    public static async providerAndKeyPairFromPublicBuffer(
        providerIdent: ProviderIdentifier,
        publicKeyBuffer: CoreBuffer,
        specOverride: Partial<KeyPairSpec>
    ): Promise<[Provider, KeyPairHandle]> {
        const provider = getProviderOrThrow(providerIdent);
        const spec = defaults(specOverride, DEFAULT_KEY_PAIR_SPEC);
        const keyPair = await provider.importPublicKey(spec, publicKeyBuffer.buffer);
        return [provider, keyPair];
    }

    public static async providerAndKeyPairFromPublicBufferWithAlgorithm(
        providerIdent: ProviderIdentifier,
        privateKeyBuffer: CoreBuffer,
        asymmetricAlgorithm?: CryptoExchangeAlgorithm | CryptoSignatureAlgorithm,
        hashAlgorithm?: CryptoHashAlgorithm
    ): Promise<CryptoLayerUtils> {
        const override: Partial<KeyPairSpec> = {
            asym_spec: asymmetricAlgorithm ? asymSpecFromCryptoAlgorithm(asymmetricAlgorithm) : undefined,
            signing_hash: hashAlgorithm ? cryptoHashFromCryptoHashAlgorithm(hashAlgorithm) : undefined
        };
        return await this.providerAndKeyPairFromPublicBuffer(providerIdent, privateKeyBuffer, override);
    }

    public static getHashAlgorithm<T extends { spec: KeyPairSpec }>(key: T): CryptoHashAlgorithm {
        return cryptoHashAlgorithmFromAsymSpec(key.spec.signing_hash);
    }
}
