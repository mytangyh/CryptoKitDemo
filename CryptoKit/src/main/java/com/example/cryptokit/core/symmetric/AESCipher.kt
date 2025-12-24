package com.example.cryptokit.core.symmetric

import com.example.cryptokit.util.SecureRandomUtil
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * AES加密实现
 */
class AESCipher(
    private val mode: String = "GCM",
    private val padding: String = "NoPadding",
    private val gcmTagLength: Int = 128
) : SymmetricCipher {

    override val algorithmName: String = "AES"
    override val defaultKeySize: Int = 256
    override val ivSize: Int = if (mode == "GCM") 12 else 16

    private val transformation: String
        get() = "AES/$mode/$padding"

    override fun encrypt(plaintext: ByteArray, key: SecretKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        when (mode) {
            "GCM" -> {
                val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
            }
            "ECB" -> {
                cipher.init(Cipher.ENCRYPT_MODE, key)
            }
            else -> {
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)
            }
        }
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(ciphertext: ByteArray, key: SecretKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(transformation)
        when (mode) {
            "GCM" -> {
                val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
                cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
            }
            "ECB" -> {
                cipher.init(Cipher.DECRYPT_MODE, key)
            }
            else -> {
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
            }
        }
        return cipher.doFinal(ciphertext)
    }

    override fun generateKey(keySize: Int): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize, SecureRandom())
        return keyGenerator.generateKey()
    }

    override fun generateIV(): ByteArray {
        return SecureRandomUtil.nextBytes(ivSize)
    }

    companion object {
        fun gcm(): AESCipher = AESCipher("GCM", "NoPadding")
        fun cbc(): AESCipher = AESCipher("CBC", "PKCS5Padding")
        fun ctr(): AESCipher = AESCipher("CTR", "NoPadding")
    }
}
