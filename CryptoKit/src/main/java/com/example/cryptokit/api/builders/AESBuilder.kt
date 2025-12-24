package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.exception.ValidationException
import com.example.cryptokit.interceptor.InterceptorChain
import com.example.cryptokit.util.CryptoLogger
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * # AES 加密 Builder
 *
 * AES (Advanced Encryption Standard) 是推荐的对称加密算法。
 * 默认使用 **AES-256-GCM** 模式，提供加密和认证保护。
 *
 * ## 支持的配置
 *
 * | 配置项 | 可选值 | 默认值 |
 * |--------|--------|--------|
 * | 模式 | GCM, CBC, CTR, ECB | GCM |
 * | 密钥长度 | 128, 192, 256 位 | 256 |
 * | GCM 标签长度 | 96, 104, 112, 120, 128 位 | 128 |
 *
 * ## 基本用法
 *
 * ```kotlin
 * // 加密（使用默认配置 AES-256-GCM）
 * val result = CryptoKit.aes().encrypt("Hello, World!")
 *
 * // 解密（使用 use 块自动清除敏感数据）
 * result.use { r ->
 *     val plaintext = CryptoKit.aes().decryptToString(r)
 * }
 * ```
 *
 * ## 自定义配置
 *
 * ```kotlin
 * // CBC 模式 + 192 位密钥
 * val result = CryptoKit.aes()
 *     .cbc()
 *     .keySize(192)
 *     .encrypt("data")
 *
 * // 使用已有密钥
 * val result = CryptoKit.aes()
 *     .key(existingKey)
 *     .iv(existingIv)
 *     .encrypt("data")
 *
 * // GCM 模式 + AAD（附加认证数据）
 * val result = CryptoKit.aes()
 *     .aad("additional auth data".toByteArray())
 *     .encrypt("data")
 * ```
 *
 * ## 安全建议
 *
 * - **推荐使用 GCM 模式**：提供加密和认证保护
 * - **避免 ECB 模式**：不提供语义安全性
 * - **每次加密使用新 IV**：默认自动生成
 * - **使用 [CipherResult.use] 块**：自动清除敏感数据
 *
 * @since 1.0.0
 * @see CipherResult
 * @see com.example.cryptokit.CryptoKit.aes
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

    private val cipher: AESCipher
        get() = AESCipher(mode, padding, gcmTagLength, aad)

    /**
     * 设置加密模式
     *
     * @param mode 加密模式：GCM, CBC, CTR, ECB
     * @return this
     * @throws ValidationException 不支持的模式
     */
    override fun mode(mode: String): AESBuilder = apply { 
        requireIn(mode.uppercase(), SUPPORTED_MODES, "mode")
        this.mode = mode.uppercase()
        this.padding = when (mode.uppercase()) {
            "GCM", "CTR" -> "NoPadding"
            "CBC", "ECB" -> "PKCS5Padding"
            else -> "NoPadding"
        }
    }

    /**
     * 使用 CBC 模式
     *
     * CBC (Cipher Block Chaining) 模式需要填充，IV 必须随机。
     *
     * @return this
     */
    fun cbc(): AESBuilder = apply { 
        this.mode = "CBC"
        this.padding = "PKCS5Padding"
    }

    /**
     * 使用 GCM 模式（默认推荐）
     *
     * GCM (Galois/Counter Mode) 提供加密和认证保护。
     * 支持附加认证数据 (AAD)。
     *
     * @return this
     */
    fun gcm(): AESBuilder = apply { 
        this.mode = "GCM"
        this.padding = "NoPadding"
    }

    /**
     * 使用 CTR 模式
     *
     * CTR (Counter) 模式是流密码模式，无需填充。
     *
     * @return this
     */
    fun ctr(): AESBuilder = apply { 
        this.mode = "CTR"
        this.padding = "NoPadding"
    }

    /**
     * 设置密钥长度
     *
     * @param size 密钥长度（位）：128, 192, 256
     * @return this
     * @throws ValidationException 无效的密钥长度
     */
    fun keySize(size: Int): AESBuilder = apply {
        validateKeySize(size, VALID_KEY_SIZES, "AES")
        this.keySize = size
    }

    /**
     * 设置密钥
     *
     * @param key AES 密钥
     * @return this
     * @throws ValidationException 无效的密钥
     */
    fun key(key: SecretKey): AESBuilder = apply { 
        validateSecretKey(key)
        this.key = key 
    }

    /**
     * 从字节数组设置密钥
     *
     * @param keyBytes 密钥字节数组（16, 24, 或 32 字节）
     * @return this
     * @throws ValidationException 无效的密钥长度
     */
    fun key(keyBytes: ByteArray): AESBuilder = apply {
        validateKeySize(keyBytes.size * 8, VALID_KEY_SIZES, "AES")
        this.key = SecretKeySpec(keyBytes, "AES")
        this.keySize = keyBytes.size * 8
    }

    /**
     * 从十六进制字符串设置密钥
     *
     * @param keyHex 十六进制密钥字符串
     * @return this
     * @throws ValidationException 无效的十六进制字符串或密钥长度
     */
    fun key(keyHex: String): AESBuilder = apply {
        val keyBytes = wrapCryptoException("Parse hex key") { keyHex.fromHex() }
        return key(keyBytes)
    }

    /**
     * 设置初始化向量 (IV)
     *
     * - GCM 模式：12 字节
     * - CBC/CTR 模式：16 字节
     *
     * @param iv 初始化向量
     * @return this
     * @throws ValidationException 无效的 IV 长度
     */
    fun iv(iv: ByteArray): AESBuilder = apply { 
        val expectedSize = if (mode == "GCM") 12 else 16
        validateIvSize(iv, expectedSize)
        this.iv = iv 
    }

    /**
     * 设置附加认证数据 (AAD)
     *
     * 仅 GCM 模式支持。AAD 不会被加密，但会被认证。
     *
     * @param aad 附加认证数据
     * @return this
     * @throws ValidationException 非 GCM 模式
     */
    fun aad(aad: ByteArray): AESBuilder = apply { 
        if (mode != "GCM") {
            throw ValidationException("AAD is only supported in GCM mode, current mode: $mode")
        }
        this.aad = aad 
    }

    /**
     * 设置 GCM 标签长度
     *
     * @param length 标签长度（位）：96, 104, 112, 120, 128
     * @return this
     * @throws ValidationException 无效的标签长度
     */
    fun gcmTagLength(length: Int): AESBuilder = apply { 
        requireIn(length, listOf(96, 104, 112, 120, 128), "gcmTagLength")
        this.gcmTagLength = length 
    }

    /**
     * 加密字节数组
     *
     * 如果未设置密钥或 IV，将自动生成。
     *
     * @param plaintext 明文
     * @return 加密结果，包含密文、密钥、IV 等
     * @throws com.example.cryptokit.exception.EncryptionException 加密失败
     * @throws ValidationException 输入验证失败
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
        requireNotEmpty(plaintext, "plaintext")
        
        val startTime = System.currentTimeMillis()
        CryptoLogger.logEncrypt("AES-$mode", plaintext.size, keySize)
        
        return wrapEncryptionException("AES-$mode") {
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "AES-$mode")
            
            val actualKey = key ?: generateKey(keySize)
            // 安全关键：GCM模式必须每次生成新nonce，防止nonce重用漏洞
            // 其他模式如CBC/CTR可以复用设置的IV
            val actualIv = if (mode == "GCM") {
                cipher.generateIV()  // GCM强制每次新nonce
            } else {
                iv ?: cipher.generateIV()
            }
            
            val ciphertext = cipher.encrypt(processedPlaintext, actualKey, actualIv)
            val processedCiphertext = InterceptorChain.afterEncrypt(ciphertext, "AES-$mode")
            
            val duration = System.currentTimeMillis() - startTime
            CryptoLogger.logEncryptComplete("AES-$mode", plaintext.size, ciphertext.size, duration)
            
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
     *
     * @param plaintext UTF-8 明文字符串
     * @return 加密结果
     * @throws com.example.cryptokit.exception.EncryptionException 加密失败
     */
    fun encrypt(plaintext: String): CipherResult {
        requireNotEmpty(plaintext, "plaintext")
        return encrypt(plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * 解密字节数组
     *
     * 必须先设置密钥和 IV。
     *
     * @param ciphertext 密文
     * @return 明文
     * @throws com.example.cryptokit.exception.DecryptionException 解密失败
     * @throws ValidationException 输入验证失败
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotEmpty(ciphertext, "ciphertext")
        val actualKey = requireNotNull(key, "key")
        val actualIv = requireNotNull(iv, "iv")
        
        val startTime = System.currentTimeMillis()
        CryptoLogger.logDecrypt("AES-$mode", ciphertext.size)
        
        return wrapDecryptionException("AES-$mode") {
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "AES-$mode")
            val plaintext = cipher.decrypt(processedCiphertext, actualKey, actualIv)
            
            val duration = System.currentTimeMillis() - startTime
            CryptoLogger.logDecryptComplete("AES-$mode", ciphertext.size, plaintext.size, duration)
            
            InterceptorChain.afterDecrypt(plaintext, "AES-$mode")
        }
    }

    /**
     * 从 [CipherResult] 解密
     *
     * 自动提取密钥、IV 和模式。
     *
     * @param result 加密结果
     * @return 明文
     * @throws com.example.cryptokit.exception.DecryptionException 解密失败
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
     *
     * @param ciphertext 密文
     * @return UTF-8 明文字符串
     */
    fun decryptToString(ciphertext: ByteArray): String = String(decrypt(ciphertext), Charsets.UTF_8)

    /**
     * 从 [CipherResult] 解密并返回字符串
     *
     * @param result 加密结果
     * @return UTF-8 明文字符串
     */
    fun decryptToString(result: CipherResult): String = String(decrypt(result), Charsets.UTF_8)

    /**
     * 生成随机 AES 密钥
     *
     * @param size 密钥长度（位），默认使用当前配置
     * @return 新生成的 AES 密钥
     * @throws ValidationException 无效的密钥长度
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
