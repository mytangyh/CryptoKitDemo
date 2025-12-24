package com.example.cryptokit.api.builders

import com.example.cryptokit.api.extensions.fromHex
import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.TripleDESCipher
import com.example.cryptokit.interceptor.InterceptorChain
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * 3DES加密Builder - 兼容旧系统
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
    fun mode(mode: String): TripleDESBuilder = apply { this.mode = mode }

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
    fun key(key: SecretKey): TripleDESBuilder = apply { this.key = key }

    /**
     * 从字节数组设置密钥
     */
    fun key(keyBytes: ByteArray): TripleDESBuilder = apply {
        this.key = SecretKeySpec(keyBytes, "DESede")
    }

    /**
     * 从十六进制字符串设置密钥
     */
    fun key(keyHex: String): TripleDESBuilder = apply {
        this.key = SecretKeySpec(keyHex.fromHex(), "DESede")
    }

    /**
     * 设置初始化向量
     */
    fun iv(iv: ByteArray): TripleDESBuilder = apply { this.iv = iv }

    /**
     * 加密字节数组
     */
    fun encrypt(plaintext: ByteArray): CipherResult {
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
        
        // 拦截器：解密前
        val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "3DES-$mode")

        val plaintext = cipher.decrypt(processedCiphertext, key!!, iv!!)
        
        // 拦截器：解密后
        return InterceptorChain.afterDecrypt(plaintext, "3DES-$mode")
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
     * 生成随机密钥（168位）
     */
    fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("DESede")
        keyGenerator.init(168, SecureRandom())
        return keyGenerator.generateKey()
    }
}
