package com.example.cryptokit.api.builders

import com.example.cryptokit.api.results.HybridCipherResult
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.hybrid.RSAAESHybridCipher
import com.example.cryptokit.core.hybrid.HybridEncryptionResult
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.exception.ValidationException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.KeyPair

/**
 * 混合加密Builder - RSA+AES混合加密
 * 
 * 金融级特性：
 * - 严格的输入验证
 * - 类型化异常处理
 * - 可配置AES密钥大小和RSA填充
 * 
 * 适用于加密大量数据，比纯RSA更高效安全
 */
class HybridBuilder : AsymmetricBuilder<HybridBuilder>() {
    
    override fun self(): HybridBuilder = this
    override fun expectedKeyAlgorithm(): String = "RSA"
    
    private var aesKeySize: Int = 256
    private var rsaPadding: String = "OAEPWithSHA-256AndMGF1Padding"

    /**
     * 设置AES密钥大小
     */
    fun aesKeySize(size: Int): HybridBuilder = apply { 
        requireIn(size, listOf(128, 192, 256), "aesKeySize")
        this.aesKeySize = size 
    }
    
    /**
     * 设置RSA填充方案
     */
    fun rsaPadding(padding: String): HybridBuilder = apply { this.rsaPadding = padding }
    
    fun oaepSha256(): HybridBuilder = apply { this.rsaPadding = "OAEPWithSHA-256AndMGF1Padding" }
    fun oaepSha1(): HybridBuilder = apply { this.rsaPadding = "OAEPWithSHA-1AndMGF1Padding" }
    fun pkcs1(): HybridBuilder = apply { this.rsaPadding = "PKCS1Padding" }
    
    /**
     * 创建配置好的cipher
     */
    private fun createCipher(): RSAAESHybridCipher {
        val rsaCipher = RSACipher(rsaPadding)
        val aesCipher = AESCipher.gcm()
        return RSAAESHybridCipher(rsaCipher, aesCipher, aesKeySize)
    }

    /**
     * 加密
     */
    fun encrypt(plaintext: ByteArray): HybridCipherResult {
        requireNotEmpty(plaintext, "plaintext")
        val key = requirePublicKey()
        
        return wrapEncryptionException("Hybrid (RSA+AES)") {
            val cipher = createCipher()
            val result = cipher.encrypt(plaintext, key)
            
            HybridCipherResult(
                encryptedKey = result.encryptedKey,
                ciphertext = result.ciphertext,
                iv = result.iv,
                authTag = result.authTag
            )
        }
    }

    fun encrypt(plaintext: String): HybridCipherResult = 
        encrypt(plaintext.toByteArray(Charsets.UTF_8))

    /**
     * 解密
     */
    fun decrypt(result: HybridCipherResult): ByteArray {
        requireNotEmpty(result.ciphertext, "ciphertext")
        val key = requirePrivateKey()
        
        return wrapDecryptionException("Hybrid (RSA+AES)") {
            val cipher = createCipher()
            val hybridResult = HybridEncryptionResult(
                encryptedKey = result.encryptedKey,
                ciphertext = result.ciphertext,
                iv = result.iv,
                authTag = result.authTag
            )
            cipher.decrypt(hybridResult, key)
        }
    }

    fun decryptToString(result: HybridCipherResult): String = 
        String(decrypt(result), Charsets.UTF_8)
}
