package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.AESCipher
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * AES加密Builder - 支持默认推荐配置
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

    private val cipher: AESCipher
        get() = AESCipher(mode, padding, gcmTagLength)

    /**
     * 设置加密模式
     */
    fun mode(mode: String): AESBuilder = apply { this.mode = mode }

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
        require(size in listOf(128, 192, 256)) { "AES key size must be 128, 192, or 256 bits" }
        this.keySize = size
    }

    /**
     * 设置密钥
     */
    fun key(key: SecretKey): AESBuilder = apply { this.key = key }

    /**
     * 从字节数组设置密钥
     */
    fun key(keyBytes: ByteArray): AESBuilder = apply {
        this.key = SecretKeySpec(keyBytes, "AES")
    }

    /**
     * 从十六进制字符串设置密钥
     */
    fun key(keyHex: String): AESBuilder = apply {
        this.key = SecretKeySpec(keyHex.fromHex(), "AES")
    }

    /**
     * 设置初始化向量
     */
    fun iv(iv: ByteArray): AESBuilder = apply { this.iv = iv }

    /**
     * 设置附加认证数据（仅GCM模式）
     */
    fun aad(aad: ByteArray): AESBuilder = apply { this.aad = aad }

    /**
     * 设置GCM标签长度（位，默认128）
     */
    fun gcmTagLength(length: Int): AESBuilder = apply { this.gcmTagLength = length }

    /**
     * 加密字节数组
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
        val actualKey = key ?: generateKey(keySize)
        val actualIv = iv ?: cipher.generateIV()
        
        val ciphertext = cipher.encrypt(plaintext, actualKey, actualIv)
        
        return CipherResult(
            ciphertext = ciphertext,
            key = actualKey,
            iv = actualIv,
            mode = mode,
            algorithm = "AES"
        )
    }

    /**
     * 加密字符串
     */
    fun encrypt(plaintext: String): CipherResult {
        return encrypt(plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * 解密字节数组
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotNull(key) { "Key must be set for decryption" }
        requireNotNull(iv) { "IV must be set for decryption" }
        
        return cipher.decrypt(ciphertext, key!!, iv!!)
    }

    /**
     * 从CipherResult解密
     */
    fun decrypt(result: CipherResult): ByteArray {
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
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(size, SecureRandom())
        return keyGenerator.generateKey()
    }
}
