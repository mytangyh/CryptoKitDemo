package com.example.cryptokit.core.asymmetric

import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

/**
 * ECC加密实现（ECDSA签名 + ECDH密钥协商）
 */
class ECCCipher(
    private val curve: String = "secp256r1"
) : AsymmetricCipher {

    override val algorithmName: String = "EC"
    override val defaultKeySize: Int = 256

    // ECC不支持直接加密，这些方法抛出异常
    override fun encrypt(plaintext: ByteArray, publicKey: PublicKey): ByteArray {
        throw UnsupportedOperationException("ECC does not support direct encryption. Use ECDH key agreement instead.")
    }

    override fun decrypt(ciphertext: ByteArray, privateKey: PrivateKey): ByteArray {
        throw UnsupportedOperationException("ECC does not support direct decryption. Use ECDH key agreement instead.")
    }

    override fun generateKeyPair(keySize: Int): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        val ecSpec = ECGenParameterSpec(curve)
        keyPairGenerator.initialize(ecSpec, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * ECDH密钥协商
     */
    fun deriveSharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(peerPublicKey, true)
        return keyAgreement.generateSecret()
    }

    companion object {
        fun p256(): ECCCipher = ECCCipher("secp256r1")
        fun p384(): ECCCipher = ECCCipher("secp384r1")
        fun p521(): ECCCipher = ECCCipher("secp521r1")
    }
}
