package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.AESCipher
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
class AESBuilder : SymmetricBuilder<AESBuilder>() {
    
    override fun self(): AESBuilder = this
    
    private var keySize: Int = 256
    private var key: SecretKey? = null
    private var iv: ByteArray? = null
    private var aad: ByteArray? = null
    private var gcmTagLength: Int = 128

    init {
        mode = "GCM"
        padding = "NoPadding"
    }

    // 延迟创建cipher，确保配置完成
    private val cipher: AESCipher
        get() = AESCipher(mode, padding, gcmTagLength, aad)

    /**
     * 设置加密模式
     */
    override fun mode(mode: String): AESBuilder = apply { 
        requireIn(mode.uppercase(), SUPPORTED_MODES, "mode")
        this.mode = mode.uppercase()
        // 自动设置合适的padding
        this.padding = when (mode.uppercase()) {
            "GCM", "CTR" -> "NoPadding"
            "CBC", "ECB" -> "PKCS5Padding"
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
     * 设置密钥长度（位）
     */
    fun keySize(size: Int): AESBuilder = apply {
        validateKeySize(size, VALID_KEY_SIZES, "AES")
        this.keySize = size
    }

    /**
     * 设置密钥
     */
    fun key(key: SecretKey): AESBuilder = apply { 
        validateSecretKey(key)
        this.key = key 
    }

    /**
     * 从字节数组设置密钥
     */
    fun key(keyBytes: ByteArray): AESBuilder = apply {
        validateKeySize(keyBytes.size * 8, VALID_KEY_SIZES, "AES")
        this.key = SecretKeySpec(keyBytes, "AES")
        this.keySize = keyBytes.size * 8
    }

    /**
     * 从十六进制字符串设置密钥
     */
    fun key(keyHex: String): AESBuilder = apply {
        val keyBytes = wrapCryptoException("Parse hex key") { keyHex.fromHex() }
        return key(keyBytes)
    }

    /**
     * 设置初始化向量
     */
    fun iv(iv: ByteArray): AESBuilder = apply { 
        val expectedSize = if (mode == "GCM") 12 else 16
        validateIvSize(iv, expectedSize)
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
        requireIn(length, listOf(96, 104, 112, 120, 128), "gcmTagLength")
        this.gcmTagLength = length 
    }

    /**
     * 加密字节数组
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
        requireNotEmpty(plaintext, "plaintext")
        
        return wrapEncryptionException("AES-$mode") {
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "AES-$mode")
            
            val actualKey = key ?: generateKey(keySize)
            val actualIv = iv ?: cipher.generateIV()
            
            val ciphertext = cipher.encrypt(processedPlaintext, actualKey, actualIv)
            val processedCiphertext = InterceptorChain.afterEncrypt(ciphertext, "AES-$mode")
            
            CipherResult(
                ciphertext = processedCiphertext,
                key = actualKey,
                iv = actualIv,
                mode = mode,
                algorithm = "AES"
            )
        }
    }

    /**
     * 加密字符串
     */
    fun encrypt(plaintext: String): CipherResult {
        requireNotEmpty(plaintext, "plaintext")
        return encrypt(plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * 解密字节数组
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotEmpty(ciphertext, "ciphertext")
        val actualKey = requireNotNull(key, "key")
        val actualIv = requireNotNull(iv, "iv")
        
        return wrapDecryptionException("AES-$mode") {
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "AES-$mode")
            val plaintext = cipher.decrypt(processedCiphertext, actualKey, actualIv)
            InterceptorChain.afterDecrypt(plaintext, "AES-$mode")
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
    fun decryptToString(ciphertext: ByteArray): String = String(decrypt(ciphertext), Charsets.UTF_8)

    /**
     * 从CipherResult解密并返回字符串
     */
    fun decryptToString(result: CipherResult): String = String(decrypt(result), Charsets.UTF_8)

    /**
     * 生成随机密钥
     */
    fun generateKey(size: Int = keySize): SecretKey {
        validateKeySize(size, VALID_KEY_SIZES, "AES")
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(size, SecureRandom())
        return keyGenerator.generateKey()
    }
    
    private fun validateSecretKey(key: SecretKey) {
        if (key.algorithm != "AES") {
            throw ValidationException("Invalid key algorithm: ${key.algorithm}, expected: AES")
        }
        val keyBytes = key.encoded
        if (keyBytes != null) {
            validateKeySize(keyBytes.size * 8, VALID_KEY_SIZES, "AES")
        }
    }
    
    companion object {
        private val VALID_KEY_SIZES = listOf(128, 192, 256)
        private val SUPPORTED_MODES = listOf("GCM", "CBC", "CTR", "ECB")
    }
}
