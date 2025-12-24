package com.example.cryptokit.core.symmetric

import com.example.cryptokit.util.SecureRandomUtil
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * 3DES加密实现
 */
class TripleDESCipher(
    private val mode: String = "CBC",
    private val padding: String = "PKCS5Padding"
) : SymmetricCipher {

    override val algorithmName: String = "DESede"
    override val defaultKeySize: Int = 168
    override val ivSize: Int = 8

    private val transformation: String
        get() = "DESede/$mode/$padding"

    override fun encrypt(plaintext: ByteArray, key: SecretKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        when (mode) {
            "ECB" -> cipher.init(Cipher.ENCRYPT_MODE, key)
            else -> cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))
        }
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(ciphertext: ByteArray, key: SecretKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        when (mode) {
            "ECB" -> cipher.init(Cipher.DECRYPT_MODE, key)
            else -> cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        }
        return cipher.doFinal(ciphertext)
    }

    override fun generateKey(keySize: Int): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("DESede")
        keyGenerator.init(168, SecureRandom())
        return keyGenerator.generateKey()
    }

    override fun generateIV(): ByteArray {
        return SecureRandomUtil.nextBytes(ivSize)
    }

    companion object {
        fun cbc(): TripleDESCipher = TripleDESCipher("CBC", "PKCS5Padding")
        fun ecb(): TripleDESCipher = TripleDESCipher("ECB", "PKCS5Padding")
    }
}
