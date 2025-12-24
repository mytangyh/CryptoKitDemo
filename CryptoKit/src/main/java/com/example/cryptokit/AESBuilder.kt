package com.example.cryptokit

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES加密Builder - 支持默认推荐配置
 * 默认配置：AES-256-GCM，自动生成密钥和IV
 */
class AESBuilder {
    private var mode: CipherMode = CipherMode.GCM
    private var padding: PaddingScheme = PaddingScheme.NO_PADDING
    private var keySize: Int = 256
    private var key: SecretKey? = null
    private var iv: ByteArray? = null
    private var aad: ByteArray? = null
    private var gcmTagLength: Int = 128

    /**
     * 设置加密模式
     */
    fun mode(mode: CipherMode): AESBuilder = apply { this.mode = mode }

    /**
     * 设置填充方案
     */
    fun padding(padding: PaddingScheme): AESBuilder = apply { this.padding = padding }

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
        val actualIv = iv ?: generateIV()
        
        val transformation = buildTransformation()
        val cipher = Cipher.getInstance(transformation)
        
        when (mode) {
            CipherMode.GCM -> {
                val gcmSpec = GCMParameterSpec(gcmTagLength, actualIv)
                cipher.init(Cipher.ENCRYPT_MODE, actualKey, gcmSpec)
                aad?.let { cipher.updateAAD(it) }
            }
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
        
        val transformation = buildTransformation()
        val cipher = Cipher.getInstance(transformation)
        
        when (mode) {
            CipherMode.GCM -> {
                val gcmSpec = GCMParameterSpec(gcmTagLength, iv)
                cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
                aad?.let { cipher.updateAAD(it) }
            }
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
     * 生成随机密钥
     */
    fun generateKey(size: Int = keySize): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(size, SecureRandom())
        return keyGenerator.generateKey()
    }

    /**
     * 生成随机IV
     */
    fun generateIV(): ByteArray {
        val ivSize = when (mode) {
            CipherMode.GCM -> 12  // GCM推荐使用12字节IV
            else -> 16           // 其他模式使用16字节IV
        }
        val iv = ByteArray(ivSize)
        SecureRandom().nextBytes(iv)
        return iv
    }

    private fun buildTransformation(): String {
        val paddingName = when (mode) {
            CipherMode.GCM, CipherMode.CTR, CipherMode.CFB, CipherMode.OFB -> PaddingScheme.NO_PADDING.paddingName
            else -> padding.paddingName
        }
        return "AES/${mode.modeName}/$paddingName"
    }
}
