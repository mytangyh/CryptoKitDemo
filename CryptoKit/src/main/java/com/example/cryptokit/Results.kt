package com.example.cryptokit

import javax.crypto.SecretKey

/**
 * 加密结果数据类
 */
data class CipherResult(
    val ciphertext: ByteArray,
    val key: SecretKey,
    val iv: ByteArray,
    val mode: CipherMode,
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

/**
 * 混合加密结果数据类
 */
data class HybridCipherResult(
    val encryptedKey: ByteArray,
    val ciphertext: ByteArray,
    val iv: ByteArray,
    val authTag: ByteArray? = null,
    val symmetricAlgorithm: SymmetricAlgorithm,
    val asymmetricAlgorithm: AsymmetricAlgorithm
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as HybridCipherResult
        return encryptedKey.contentEquals(other.encryptedKey) &&
                ciphertext.contentEquals(other.ciphertext) &&
                iv.contentEquals(other.iv) &&
                authTag?.contentEquals(other.authTag ?: byteArrayOf()) == true &&
                symmetricAlgorithm == other.symmetricAlgorithm &&
                asymmetricAlgorithm == other.asymmetricAlgorithm
    }

    override fun hashCode(): Int {
        var result = encryptedKey.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + (authTag?.contentHashCode() ?: 0)
        result = 31 * result + symmetricAlgorithm.hashCode()
        result = 31 * result + asymmetricAlgorithm.hashCode()
        return result
    }
}

/**
 * 密钥存储选项
 */
data class KeyStoreOptions(
    val requireUserAuthentication: Boolean = false,
    val authenticationTimeout: Int = 0,
    val requireBiometric: Boolean = false,
    val invalidatedByBiometricEnrollment: Boolean = true,
    val isStrongBoxBacked: Boolean = false
)

/**
 * 密钥生成选项
 */
data class KeyGenOptions(
    val requireUserAuthentication: Boolean = false,
    val authenticationTimeout: Int = 0,
    val requireBiometric: Boolean = false,
    val invalidatedByBiometricEnrollment: Boolean = true,
    val isStrongBoxBacked: Boolean = false
)
