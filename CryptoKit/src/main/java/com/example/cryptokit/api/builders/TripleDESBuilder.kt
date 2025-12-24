package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.TripleDESCipher
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
class TripleDESBuilder : SymmetricBuilder<TripleDESBuilder>() {
    
    override fun self(): TripleDESBuilder = this
    
    private var key: SecretKey? = null
    private var iv: ByteArray? = null

    init {
        mode = "CBC"
        padding = "PKCS5Padding"
    }

    private val cipher: TripleDESCipher
        get() = TripleDESCipher(mode, padding)

    /**
     * 设置加密模式
     */
    override fun mode(mode: String): TripleDESBuilder = apply { 
        requireIn(mode.uppercase(), SUPPORTED_MODES, "mode")
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
     * 设置密钥
     */
    fun key(key: SecretKey): TripleDESBuilder = apply { 
        validateSecretKey(key)
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
        val keyBytes = wrapCryptoException("Parse hex key") { keyHex.fromHex() }
        return key(keyBytes)
    }

    /**
     * 设置初始化向量
     */
    fun iv(iv: ByteArray): TripleDESBuilder = apply { 
        validateIvSize(iv, 8)
        this.iv = iv 
    }

    /**
     * 加密字节数组
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
        requireNotEmpty(plaintext, "plaintext")
        
        return wrapEncryptionException("3DES-$mode") {
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "3DES-$mode")
            
            val actualKey = key ?: generateKey()
            val actualIv = iv ?: cipher.generateIV()

            val ciphertext = cipher.encrypt(processedPlaintext, actualKey, actualIv)
            val processedCiphertext = InterceptorChain.afterEncrypt(ciphertext, "3DES-$mode")

            CipherResult(
                ciphertext = processedCiphertext,
                key = actualKey,
                iv = actualIv,
                mode = mode,
                algorithm = "DESede"
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
        val actualIv = if (mode != "ECB") requireNotNull(iv, "iv") else ByteArray(8)
        
        return wrapDecryptionException("3DES-$mode") {
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "3DES-$mode")
            val plaintext = cipher.decrypt(processedCiphertext, actualKey, actualIv)
            InterceptorChain.afterDecrypt(plaintext, "3DES-$mode")
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
     * 生成随机密钥（168位）
     */
    fun generateKey(): SecretKey = wrapCryptoException("Generate 3DES key") {
        val keyGenerator = KeyGenerator.getInstance("DESede")
        keyGenerator.init(168, SecureRandom())
        keyGenerator.generateKey()
    }
    
    private fun validateSecretKey(key: SecretKey) {
        // 使用不区分大小写的比较，因为不同JCE provider可能返回不同大小写
        if (!key.algorithm.equals("DESede", ignoreCase = true)) {
            throw ValidationException("Invalid key algorithm: ${key.algorithm}, expected: DESede")
        }
    }
    
    companion object {
        private val SUPPORTED_MODES = listOf("CBC", "ECB")
    }
}
