package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.exception.DecryptionException
import com.example.cryptokit.exception.EncryptionException
import com.example.cryptokit.exception.ValidationException
import com.example.cryptokit.interceptor.InterceptorChain
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * AES加密Builder - 支持默认推荐配置
 * 
 * 金融级特性：
 * - 严格的输入验证
 * - 完善的异常处理
 * - AAD（附加认证数据）支持
 * - 线程安全
 * 
 * 默认配置：AES-256-GCM，自动生成密钥和IV
 */
class AESBuilder {
    private var mode: String = "GCM"
    private var padding: String = "NoPadding"
    private var keySize: Int = 256
    private var key: SecretKey? = null
    private var iv: ByteArray? = null
    private var aad: ByteArray? = null
    private var gcmTagLength: Int = 128

    // 延迟创建cipher，确保配置完成
    private val cipher: AESCipher
        get() = AESCipher(mode, padding, gcmTagLength, aad)

    /**
     * 设置加密模式
     */
    fun mode(mode: String): AESBuilder = apply { 
        require(mode.uppercase() in SUPPORTED_MODES) { 
            "Unsupported mode: $mode, supported: $SUPPORTED_MODES" 
        }
        this.mode = mode.uppercase()
        // 自动设置合适的padding
        this.padding = when (mode.uppercase()) {
            "GCM", "CTR" -> "NoPadding"
            "CBC" -> "PKCS5Padding"
            "ECB" -> "PKCS5Padding"
            else -> "NoPadding"
        }
    }

    /**
     * CBC模式
     */
    fun cbc(): AESBuilder = apply { 
        this.mode = "CBC"
        this.padding = "PKCS5Padding"
    }

    /**
     * GCM模式（默认推荐）
     */
    fun gcm(): AESBuilder = apply { 
        this.mode = "GCM"
        this.padding = "NoPadding"
    }

    /**
     * CTR模式
     */
    fun ctr(): AESBuilder = apply { 
        this.mode = "CTR"
        this.padding = "NoPadding"
    }

    /**
     * 设置填充方案
     */
    fun padding(padding: String): AESBuilder = apply { this.padding = padding }

    /**
     * 设置密钥长度（位）
     */
    fun keySize(size: Int): AESBuilder = apply {
        if (size !in VALID_KEY_SIZES) {
            throw ValidationException.invalidKeySize(VALID_KEY_SIZES, size)
        }
        this.keySize = size
    }

    /**
     * 设置密钥
     */
    fun key(key: SecretKey): AESBuilder = apply { 
        validateKey(key)
        this.key = key 
    }

    /**
     * 从字节数组设置密钥
     */
    fun key(keyBytes: ByteArray): AESBuilder = apply {
        if (keyBytes.size !in listOf(16, 24, 32)) {
            throw ValidationException.invalidKeySize(
                VALID_KEY_SIZES, 
                keyBytes.size * 8
            )
        }
        this.key = SecretKeySpec(keyBytes, "AES")
        this.keySize = keyBytes.size * 8
    }

    /**
     * 从十六进制字符串设置密钥
     */
    fun key(keyHex: String): AESBuilder = apply {
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
    fun iv(iv: ByteArray): AESBuilder = apply { 
        val expectedSize = if (mode == "GCM") 12 else 16
        if (iv.size != expectedSize) {
            throw ValidationException.invalidIvSize(expectedSize, iv.size)
        }
        this.iv = iv 
    }

    /**
     * 设置附加认证数据（仅GCM模式）
     */
    fun aad(aad: ByteArray): AESBuilder = apply { 
        if (mode != "GCM") {
            throw ValidationException("AAD is only supported in GCM mode, current mode: $mode")
        }
        this.aad = aad 
    }

    /**
     * 设置GCM标签长度（位，默认128）
     */
    fun gcmTagLength(length: Int): AESBuilder = apply { 
        if (length !in listOf(96, 104, 112, 120, 128)) {
            throw ValidationException("Invalid GCM tag length: $length, must be 96, 104, 112, 120, or 128")
        }
        this.gcmTagLength = length 
    }

    /**
     * 加密字节数组
     * 
     * @throws EncryptionException 加密失败时抛出
     * @throws ValidationException 输入验证失败时抛出
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
        // 输入验证
        if (plaintext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        
        try {
            // 拦截器：加密前
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "AES-$mode")
            
            val actualKey = key ?: generateKey(keySize)
            val actualIv = iv ?: cipher.generateIV()
            
            val ciphertext = cipher.encrypt(processedPlaintext, actualKey, actualIv)
            
            // 拦截器：加密后
            val processedCiphertext = InterceptorChain.afterEncrypt(ciphertext, "AES-$mode")
            
            return CipherResult(
                ciphertext = processedCiphertext,
                key = actualKey,
                iv = actualIv,
                mode = mode,
                algorithm = "AES"
            )
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw EncryptionException("AES-$mode encryption failed: ${e.message}", e)
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
     * @throws DecryptionException 解密失败时抛出
     * @throws ValidationException 输入验证失败时抛出
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        // 输入验证
        if (ciphertext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (key == null) {
            throw ValidationException.nullParameter("key")
        }
        if (iv == null) {
            throw ValidationException.nullParameter("iv")
        }
        
        try {
            // 拦截器：解密前
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "AES-$mode")
            
            val plaintext = cipher.decrypt(processedCiphertext, key!!, iv!!)
            
            // 拦截器：解密后
            return InterceptorChain.afterDecrypt(plaintext, "AES-$mode")
        } catch (e: ValidationException) {
            throw e
        } catch (e: javax.crypto.AEADBadTagException) {
            throw DecryptionException.authenticationFailed(e)
        } catch (e: Exception) {
            throw DecryptionException("AES-$mode decryption failed: ${e.message}", e)
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
     * 生成随机密钥
     */
    fun generateKey(size: Int = keySize): SecretKey {
        if (size !in VALID_KEY_SIZES) {
            throw ValidationException.invalidKeySize(VALID_KEY_SIZES, size)
        }
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(size, SecureRandom())
        return keyGenerator.generateKey()
    }
    
    /**
     * 验证密钥有效性
     */
    private fun validateKey(key: SecretKey) {
        if (key.algorithm != "AES") {
            throw ValidationException("Invalid key algorithm: ${key.algorithm}, expected: AES")
        }
        val keyBytes = key.encoded
        if (keyBytes != null && keyBytes.size !in listOf(16, 24, 32)) {
            throw ValidationException.invalidKeySize(VALID_KEY_SIZES, keyBytes.size * 8)
        }
    }
    
    companion object {
        private val VALID_KEY_SIZES = listOf(128, 192, 256)
        private val SUPPORTED_MODES = listOf("GCM", "CBC", "CTR", "ECB")
    }
}
