package com.example.cryptokit.core.hybrid

import java.security.PrivateKey
import java.security.PublicKey

/**
 * 混合加密接口
 */
interface HybridCipher {
    /**
     * 混合加密
     */
    fun encrypt(plaintext: ByteArray, publicKey: PublicKey): HybridEncryptionResult

    /**
     * 混合解密
     */
    fun decrypt(result: HybridEncryptionResult, privateKey: PrivateKey): ByteArray
}

/**
 * 混合加密结果
 */
data class HybridEncryptionResult(
    val encryptedKey: ByteArray,
    val ciphertext: ByteArray,
    val iv: ByteArray,
    val authTag: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as HybridEncryptionResult
        return encryptedKey.contentEquals(other.encryptedKey) &&
                ciphertext.contentEquals(other.ciphertext) &&
                iv.contentEquals(other.iv) &&
                authTag?.contentEquals(other.authTag ?: byteArrayOf()) == true
    }

    override fun hashCode(): Int {
        var result = encryptedKey.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + (authTag?.contentHashCode() ?: 0)
        return result
    }
}
