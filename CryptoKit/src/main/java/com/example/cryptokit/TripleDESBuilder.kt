package com.example.cryptokit

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 3DES加密Builder - 兼容旧系统
 * 默认配置：3DES-CBC-PKCS5Padding
 */
class TripleDESBuilder {
    private var mode: CipherMode = CipherMode.CBC
    private var padding: PaddingScheme = PaddingScheme.PKCS5_PADDING
    private var key: SecretKey? = null
    private var iv: ByteArray? = null

    /**
     * 设置加密模式
     */
    fun mode(mode: CipherMode): TripleDESBuilder = apply { this.mode = mode }

    /**
     * 设置填充方案
     */
    fun padding(padding: PaddingScheme): TripleDESBuilder = apply { this.padding = padding }

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
        val actualKey = key ?: generateKey()
        val actualIv = iv ?: generateIV()
        
        val transformation = buildTransformation()
        val cipher = Cipher.getInstance(transformation)
        
        when (mode) {
            CipherMode.ECB -> {
                cipher.init(Cipher.ENCRYPT_MODE, actualKey)
            }
            else -> {
                val ivSpec = IvParameterSpec(actualIv)
                cipher.init(Cipher.ENCRYPT_MODE, actualKey, ivSpec)
            }
        }
        
        val ciphertext = cipher.doFinal(plaintext)
        
        return CipherResult(
            ciphertext = ciphertext,
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
        
        val transformation = buildTransformation()
        val cipher = Cipher.getInstance(transformation)
        
        when (mode) {
            CipherMode.ECB -> {
                cipher.init(Cipher.DECRYPT_MODE, key)
            }
            else -> {
                val ivSpec = IvParameterSpec(iv)
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
            }
        }
        
        return cipher.doFinal(ciphertext)
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

    /**
     * 生成随机IV
     */
    fun generateIV(): ByteArray {
        val iv = ByteArray(8)  // 3DES使用8字节IV
        SecureRandom().nextBytes(iv)
        return iv
    }

    private fun buildTransformation(): String {
        return "DESede/${mode.modeName}/${padding.paddingName}"
    }
}
