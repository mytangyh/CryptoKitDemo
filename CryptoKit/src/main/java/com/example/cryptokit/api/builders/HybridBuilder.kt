package com.example.cryptokit.api.builders

import com.example.cryptokit.api.results.HybridCipherResult
import com.example.cryptokit.core.hybrid.RSAAESHybridCipher
import java.security.PrivateKey
import java.security.PublicKey

/**
 * 混合加密Builder - RSA+AES混合加密
 */
class HybridBuilder {
    private var aesKeySize: Int = 256
    private var rsaPadding: String = "OAEPWithSHA-256AndMGF1Padding"
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    fun aesKeySize(size: Int): HybridBuilder = apply { this.aesKeySize = size }
    fun rsaPadding(padding: String): HybridBuilder = apply { this.rsaPadding = padding }

    fun publicKey(key: PublicKey): HybridBuilder = apply { this.publicKey = key }
    fun privateKey(key: PrivateKey): HybridBuilder = apply { this.privateKey = key }

    fun encrypt(plaintext: ByteArray): HybridCipherResult {
        requireNotNull(publicKey) { "Public key must be set for encryption" }
        
        val cipher = RSAAESHybridCipher.default()
        val result = cipher.encrypt(plaintext, publicKey!!)
        
        return HybridCipherResult(
            encryptedKey = result.encryptedKey,
            ciphertext = result.ciphertext,
            iv = result.iv,
            authTag = result.authTag
        )
    }

    fun encrypt(plaintext: String): HybridCipherResult = 
        encrypt(plaintext.toByteArray(Charsets.UTF_8))

    fun decrypt(result: HybridCipherResult): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for decryption" }
        
        val cipher = RSAAESHybridCipher.default()
        val hybridResult = com.example.cryptokit.core.hybrid.HybridEncryptionResult(
            encryptedKey = result.encryptedKey,
            ciphertext = result.ciphertext,
            iv = result.iv,
            authTag = result.authTag
        )
        
        return cipher.decrypt(hybridResult, privateKey!!)
    }

    fun decryptToString(result: HybridCipherResult): String = 
        String(decrypt(result), Charsets.UTF_8)
}
