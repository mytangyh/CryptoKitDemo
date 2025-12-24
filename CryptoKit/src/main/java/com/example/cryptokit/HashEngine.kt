package com.example.cryptokit

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * 哈希引擎 - 提供哈希计算、HMAC和密钥派生功能
 */
class HashEngine(private val algorithm: HashAlgorithm) {

    private var messageDigest: MessageDigest = MessageDigest.getInstance(algorithm.algorithmName)

    /**
     * 计算哈希值
     */
    fun digest(data: ByteArray): ByteArray {
        return messageDigest.digest(data)
    }

    /**
     * 计算字符串的哈希值
     */
    fun digest(data: String): ByteArray {
        return digest(data.toByteArray(Charsets.UTF_8))
    }

    /**
     * 计算哈希值并返回十六进制字符串
     */
    fun digestToHex(data: ByteArray): String {
        return digest(data).toHex()
    }

    /**
     * 计算字符串的哈希值并返回十六进制字符串
     */
    fun digestToHex(data: String): String {
        return digest(data).toHex()
    }

    /**
     * 更新数据（用于流式哈希）
     */
    fun update(data: ByteArray): HashEngine {
        messageDigest.update(data)
        return this
    }

    /**
     * 更新字符串数据
     */
    fun update(data: String): HashEngine {
        messageDigest.update(data.toByteArray(Charsets.UTF_8))
        return this
    }

    /**
     * 完成哈希计算
     */
    fun finish(): ByteArray {
        return messageDigest.digest()
    }

    /**
     * 重置哈希引擎
     */
    fun reset(): HashEngine {
        messageDigest.reset()
        return this
    }

    companion object {
        /**
         * 计算HMAC
         */
        fun hmac(
            data: ByteArray,
            key: ByteArray,
            algorithm: HashAlgorithm = HashAlgorithm.SHA256
        ): ByteArray {
            val hmacAlgorithm = "Hmac${algorithm.algorithmName.replace("-", "")}"
            val mac = Mac.getInstance(hmacAlgorithm)
            val secretKey = SecretKeySpec(key, hmacAlgorithm)
            mac.init(secretKey)
            return mac.doFinal(data)
        }

        /**
         * 计算字符串的HMAC
         */
        fun hmac(
            data: String,
            key: ByteArray,
            algorithm: HashAlgorithm = HashAlgorithm.SHA256
        ): ByteArray {
            return hmac(data.toByteArray(Charsets.UTF_8), key, algorithm)
        }

        /**
         * 密钥派生（PBKDF2）
         */
        fun deriveKey(
            password: CharArray,
            salt: ByteArray,
            iterations: Int = 10000,
            keyLength: Int = 256,
            algorithm: HashAlgorithm = HashAlgorithm.SHA256
        ): ByteArray {
            val pbkdf2Algorithm = "PBKDF2WithHmac${algorithm.algorithmName.replace("-", "")}"
            val factory = SecretKeyFactory.getInstance(pbkdf2Algorithm)
            val spec = PBEKeySpec(password, salt, iterations, keyLength)
            return factory.generateSecret(spec).encoded
        }

        /**
         * 生成随机盐
         */
        fun generateSalt(length: Int = 16): ByteArray {
            val salt = ByteArray(length)
            SecureRandom().nextBytes(salt)
            return salt
        }
    }
}
