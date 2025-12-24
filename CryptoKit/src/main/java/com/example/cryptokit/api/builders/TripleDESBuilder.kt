package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.TripleDESCipher
import com.example.cryptokit.exception.DecryptionException
import com.example.cryptokit.exception.EncryptionException
import com.example.cryptokit.exception.ValidationException
import com.example.cryptokit.interceptor.InterceptorChain
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * 3DES加密Builder - 兼容旧系统
 * 
 * 金融级特性：
 * - 严格的输入验证
 * - 类型化异常处理
 * - 兼容遗留系统
 * 
 * ⚠️ 警告：3DES已不推荐用于新项目，仅用于兼容旧系统
 * 
 * 默认配置：3DES-CBC-PKCS5Padding
 */
class TripleDESBuilder {
    private var mode: String = "CBC"
    private var padding: String = "PKCS5Padding"
    private var key: SecretKey? = null
    private var iv: ByteArray? = null

    private val cipher: TripleDESCipher
        get() = TripleDESCipher(mode, padding)

    /**
     * 设置加密模式
     */
    fun mode(mode: String): TripleDESBuilder = apply { 
        if (mode.uppercase() !in SUPPORTED_MODES) {
            throw ValidationException("Unsupported 3DES mode: $mode, supported: $SUPPORTED_MODES")
        }
        this.mode = mode.uppercase()
    }

    /**
     * CBC模式（默认推荐）
     */
    fun cbc(): TripleDESBuilder = apply {
        this.mode = "CBC"
        this.padding = "PKCS5Padding"
    }

    /**
     * ECB模式（不推荐，仅用于兼容）
     */
    fun ecb(): TripleDESBuilder = apply {
        this.mode = "ECB"
        this.padding = "PKCS5Padding"
    }

    /**
     * 设置填充方案
     */
    fun padding(padding: String): TripleDESBuilder = apply { this.padding = padding }

    /**
     * 设置密钥
     */
    fun key(key: SecretKey): TripleDESBuilder = apply { 
        validateKey(key)
        this.key = key 
    }

    /**
     * 从字节数组设置密钥
     */
    fun key(keyBytes: ByteArray): TripleDESBuilder = apply {
        if (keyBytes.size !in listOf(16, 24)) {
            throw ValidationException("Invalid 3DES key size: ${keyBytes.size} bytes, expected 16 or 24 bytes")
        }
        this.key = SecretKeySpec(keyBytes, "DESede")
    }

    /**
     * 从十六进制字符串设置密钥
     */
    fun key(keyHex: String): TripleDESBuilder = apply {
        val keyBytes = try {
            keyHex.fromHex()
        } catch (e: Exception) {
            throw ValidationException("Invalid hex key string", e)
        }
        return key(keyBytes)
    }

    /**
     * 设置初始化向量
     */
    fun iv(iv: ByteArray): TripleDESBuilder = apply { 
        if (iv.size != 8) {
            throw ValidationException.invalidIvSize(8, iv.size)
        }
        this.iv = iv 
    }

    /**
     * 加密字节数组
     * 
     * @throws EncryptionException 加密失败
     * @throws ValidationException 输入验证失败
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
        if (plaintext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        
        try {
            // 拦截器：加密前
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "3DES-$mode")
            
            val actualKey = key ?: generateKey()
            val actualIv = iv ?: cipher.generateIV()

            val ciphertext = cipher.encrypt(processedPlaintext, actualKey, actualIv)
            
            // 拦截器：加密后
            val processedCiphertext = InterceptorChain.afterEncrypt(ciphertext, "3DES-$mode")

            return CipherResult(
                ciphertext = processedCiphertext,
                key = actualKey,
                iv = actualIv,
                mode = mode,
                algorithm = "DESede"
            )
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw EncryptionException("3DES-$mode encryption failed: ${e.message}", e)
        }
    }

    /**
     * 加密字符串
     */
    fun encrypt(plaintext: String): CipherResult {
        if (plaintext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        return encrypt(plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * 解密字节数组
     * 
     * @throws DecryptionException 解密失败
     * @throws ValidationException 输入验证失败
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        if (ciphertext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (key == null) {
            throw ValidationException.nullParameter("key")
        }
        if (iv == null && mode != "ECB") {
            throw ValidationException.nullParameter("iv")
        }
        
        try {
            // 拦截器：解密前
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "3DES-$mode")

            val plaintext = cipher.decrypt(processedCiphertext, key!!, iv ?: ByteArray(8))
            
            // 拦截器：解密后
            return InterceptorChain.afterDecrypt(plaintext, "3DES-$mode")
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw DecryptionException("3DES-$mode decryption failed: ${e.message}", e)
        }
    }

    /**
     * 从CipherResult解密
     */
    fun decrypt(result: CipherResult): ByteArray {
        require(!result.isCleared()) { "CipherResult has been cleared" }
        return key(result.key)
            .iv(result.iv)
            .mode(result.mode)
            .decrypt(result.ciphertext)
    }

    /**
     * 解密并返回字符串
     */
    fun decryptToString(ciphertext: ByteArray): String {
        return String(decrypt(ciphertext), Charsets.UTF_8)
    }

    /**
     * 从CipherResult解密并返回字符串
     */
    fun decryptToString(result: CipherResult): String {
        return String(decrypt(result), Charsets.UTF_8)
    }

    /**
     * 生成随机密钥（168位）
     */
    fun generateKey(): SecretKey {
        try {
            val keyGenerator = KeyGenerator.getInstance("DESede")
            keyGenerator.init(168, SecureRandom())
            return keyGenerator.generateKey()
        } catch (e: Exception) {
            throw EncryptionException("Failed to generate 3DES key: ${e.message}", e)
        }
    }
    
    private fun validateKey(key: SecretKey) {
        if (key.algorithm != "DESede") {
            throw ValidationException("Invalid key algorithm: ${key.algorithm}, expected: DESede")
        }
    }
    
    companion object {
        private val SUPPORTED_MODES = listOf("CBC", "ECB")
    }
}
