package com.example.cryptokit.api.results

/**
 * 混合加密结果
 */
data class HybridCipherResult(
    val encryptedKey: ByteArray,
    val ciphertext: ByteArray,
    val iv: ByteArray,
    val authTag: ByteArray? = null,
    val symmetricAlgorithm: String = "AES",
    val asymmetricAlgorithm: String = "RSA"
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
