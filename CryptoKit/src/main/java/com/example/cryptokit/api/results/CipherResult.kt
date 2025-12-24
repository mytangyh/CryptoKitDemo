package com.example.cryptokit.api.results

import javax.crypto.SecretKey

/**
 * 对称加密结果
 */
data class CipherResult(
    val ciphertext: ByteArray,
    val key: SecretKey,
    val iv: ByteArray,
    val mode: String,
    val algorithm: String,
    val authTag: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as CipherResult
        return ciphertext.contentEquals(other.ciphertext) &&
                key == other.key &&
                iv.contentEquals(other.iv) &&
                mode == other.mode &&
                algorithm == other.algorithm &&
                authTag?.contentEquals(other.authTag ?: byteArrayOf()) == true
    }

    override fun hashCode(): Int {
        var result = ciphertext.contentHashCode()
        result = 31 * result + key.hashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + mode.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (authTag?.contentHashCode() ?: 0)
        return result
    }
}
