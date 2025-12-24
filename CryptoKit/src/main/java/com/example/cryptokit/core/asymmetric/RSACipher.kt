package com.example.cryptokit.core.asymmetric

import java.security.*
import javax.crypto.Cipher

/**
 * RSA加密实现
 */
class RSACipher(
    private val padding: String = "OAEPWithSHA-256AndMGF1Padding"
) : AsymmetricCipher {

    override val algorithmName: String = "RSA"
    override val defaultKeySize: Int = 2048

    private val transformation: String
        get() = "RSA/ECB/$padding"

    override fun encrypt(plaintext: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(ciphertext: ByteArray, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(ciphertext)
    }

    override fun generateKeyPair(keySize: Int): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    companion object {
        fun oaepSha256(): RSACipher = RSACipher("OAEPWithSHA-256AndMGF1Padding")
        fun oaepSha1(): RSACipher = RSACipher("OAEPWithSHA-1AndMGF1Padding")
        fun pkcs1(): RSACipher = RSACipher("PKCS1Padding")
    }
}
