package com.example.cryptokit.api.builders

import com.example.cryptokit.api.results.HybridCipherResult
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.hybrid.RSAAESHybridCipher
import com.example.cryptokit.core.hybrid.HybridEncryptionResult
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.exception.DecryptionException
import com.example.cryptokit.exception.EncryptionException
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
class HybridBuilder {
    private var aesKeySize: Int = 256
    private var rsaPadding: String = "OAEPWithSHA-256AndMGF1Padding"
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    /**
     * 设置AES密钥大小
     */
    fun aesKeySize(size: Int): HybridBuilder = apply { 
        if (size !in listOf(128, 192, 256)) {
            throw ValidationException.invalidKeySize(listOf(128, 192, 256), size)
        }
        this.aesKeySize = size 
    }
    
    /**
     * 设置RSA填充方案
     */
    fun rsaPadding(padding: String): HybridBuilder = apply { this.rsaPadding = padding }
    
    fun oaepSha256(): HybridBuilder = apply { this.rsaPadding = "OAEPWithSHA-256AndMGF1Padding" }
    fun oaepSha1(): HybridBuilder = apply { this.rsaPadding = "OAEPWithSHA-1AndMGF1Padding" }
    fun pkcs1(): HybridBuilder = apply { this.rsaPadding = "PKCS1Padding" }

    fun publicKey(key: PublicKey): HybridBuilder = apply { 
        validatePublicKey(key)
        this.publicKey = key 
    }
    
    fun privateKey(key: PrivateKey): HybridBuilder = apply { 
        validatePrivateKey(key)
        this.privateKey = key 
    }
    
    /**
     * 同时设置公钥和私钥
     */
    fun keyPair(keyPair: KeyPair): HybridBuilder = apply {
        this.publicKey = keyPair.public
        this.privateKey = keyPair.private
    }
    
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
     * 
     * @throws EncryptionException 加密失败
     * @throws ValidationException 输入验证失败
     */
    fun encrypt(plaintext: ByteArray): HybridCipherResult {
        if (plaintext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (publicKey == null) {
            throw ValidationException.nullParameter("publicKey")
        }
        
        try {
            val cipher = createCipher()
            val result = cipher.encrypt(plaintext, publicKey!!)
            
            return HybridCipherResult(
                encryptedKey = result.encryptedKey,
                ciphertext = result.ciphertext,
                iv = result.iv,
                authTag = result.authTag
            )
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw EncryptionException("Hybrid encryption failed: ${e.message}", e)
        }
    }

    fun encrypt(plaintext: String): HybridCipherResult = 
        encrypt(plaintext.toByteArray(Charsets.UTF_8))

    /**
     * 解密
     * 
     * @throws DecryptionException 解密失败
     * @throws ValidationException 输入验证失败
     */
    fun decrypt(result: HybridCipherResult): ByteArray {
        if (result.ciphertext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (privateKey == null) {
            throw ValidationException.nullParameter("privateKey")
        }
        
        try {
            val cipher = createCipher()
            val hybridResult = HybridEncryptionResult(
                encryptedKey = result.encryptedKey,
                ciphertext = result.ciphertext,
                iv = result.iv,
                authTag = result.authTag
            )
            
            return cipher.decrypt(hybridResult, privateKey!!)
        } catch (e: ValidationException) {
            throw e
        } catch (e: javax.crypto.AEADBadTagException) {
            throw DecryptionException.authenticationFailed(e)
        } catch (e: Exception) {
            throw DecryptionException("Hybrid decryption failed: ${e.message}", e)
        }
    }

    fun decryptToString(result: HybridCipherResult): String = 
        String(decrypt(result), Charsets.UTF_8)
    
    private fun validatePublicKey(key: PublicKey) {
        if (key.algorithm != "RSA") {
            throw ValidationException("Invalid public key algorithm: ${key.algorithm}, expected: RSA")
        }
    }
    
    private fun validatePrivateKey(key: PrivateKey) {
        if (key.algorithm != "RSA") {
            throw ValidationException("Invalid private key algorithm: ${key.algorithm}, expected: RSA")
        }
    }
}
