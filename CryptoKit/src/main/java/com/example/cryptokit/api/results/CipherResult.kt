package com.example.cryptokit.api.results

import com.example.cryptokit.util.SecureUtils
import java.io.Closeable
import javax.crypto.SecretKey

/**
 * # 对称加密结果
 *
 * 封装对称加密操作的结果，包含密文、密钥、IV 等信息。
 * 实现 [Closeable] 接口，支持自动清除敏感数据。
 *
 * ## 安全特性
 *
 * - **自动擦除**: 调用 [close] 方法会安全擦除密钥、IV 和认证标签
 * - **恒定时间比较**: [equals] 使用恒定时间比较防止时序攻击
 * - **状态检查**: 使用 [isCleared] 检查数据是否已清除
 *
 * ## 推荐用法
 *
 * 使用 `use` 块确保敏感数据自动清除：
 *
 * ```kotlin
 * CryptoKit.aes().encrypt("data").use { result ->
 *     // 使用 result
 *     val ciphertext = result.ciphertext
 * } // 自动调用 close()，清除敏感数据
 * ```
 *
 * ## 数据传输
 *
 * 使用 [toTransportFormat] 获取不含敏感密钥的传输格式：
 *
 * ```kotlin
 * val transport = result.toTransportFormat()
 * // transport 只包含 ciphertext、iv、mode、algorithm
 * // 不包含密钥
 * ```
 *
 * @property ciphertext 加密后的密文
 * @property key 加密使用的密钥
 * @property iv 初始化向量
 * @property mode 加密模式（如 "GCM"、"CBC"）
 * @property algorithm 加密算法（如 "AES"）
 * @property authTag GCM 模式的认证标签（可选）
 *
 * @since 1.0.0
 * @see com.example.cryptokit.api.builders.AESBuilder
 * @see com.example.cryptokit.CryptoKit.aes
 */
data class CipherResult(
    val ciphertext: ByteArray,
    val key: SecretKey,
    val iv: ByteArray,
    val mode: String,
    val algorithm: String,
    val authTag: ByteArray? = null
) : Closeable {
    
    @Volatile
    private var isWiped = false
    
    /**
     * 安全清除敏感数据
     *
     * 清除密钥、IV 和认证标签。调用后 [isCleared] 返回 true。
     *
     * **注意**: 密文不会被清除，因为通常需要存储或传输。
     */
    override fun close() {
        if (!isWiped) {
            // 安全擦除密钥
            key.encoded?.let { SecureUtils.wipe(it) }
            // 安全擦除IV
            SecureUtils.wipe(iv)
            // 安全擦除认证标签
            authTag?.let { SecureUtils.wipe(it) }
            isWiped = true
        }
    }
    
    /**
     * 检查敏感数据是否已被清除
     *
     * @return 如果已调用 [close]，返回 true
     */
    fun isCleared(): Boolean = isWiped
    
    /**
     * 验证结果未被清除
     *
     * @throws IllegalStateException 如果已被清除
     */
    fun validate() {
        check(!isWiped) { "CipherResult has been cleared and cannot be used" }
    }
    
    /**
     * 获取密钥字节数组
     *
     * **⚠️ 警告**: 调用方负责清除返回的字节数组！
     *
     * ```kotlin
     * val keyBytes = result.getKeyBytes()
     * try {
     *     // 使用 keyBytes
     * } finally {
     *     CryptoKit.secure.wipe(keyBytes)
     * }
     * ```
     *
     * @return 密钥的字节数组副本
     * @throws IllegalStateException 如果结果已被清除
     */
    fun getKeyBytes(): ByteArray {
        validate()
        return key.encoded?.copyOf() ?: ByteArray(0)
    }
    
    /**
     * 转换为安全传输格式
     *
     * 返回不包含敏感密钥的 Map，适合序列化传输。
     * 接收方需要通过安全通道获取密钥。
     *
     * @return 包含 ciphertext、iv、mode、algorithm 的 Map
     */
    fun toTransportFormat(): Map<String, Any> {
        return mapOf(
            "ciphertext" to ciphertext,
            "iv" to iv,
            "mode" to mode,
            "algorithm" to algorithm
        ).let { map ->
            if (authTag != null) map + ("authTag" to authTag) else map
        }
    }

    /**
     * 使用恒定时间比较
     *
     * 防止时序攻击。
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CipherResult

        if (!SecureUtils.constantTimeEquals(ciphertext, other.ciphertext)) return false
        if (!SecureUtils.constantTimeEquals(iv, other.iv)) return false
        if (mode != other.mode) return false
        if (algorithm != other.algorithm) return false
        if (!SecureUtils.constantTimeEquals(authTag, other.authTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ciphertext.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + mode.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (authTag?.contentHashCode() ?: 0)
        return result
    }
    
    companion object {
        /**
         * 从传输格式重建 CipherResult
         *
         * **注意**: 密钥需要单独提供。
         *
         * @param data 传输格式数据
         * @param key 加密密钥
         * @return CipherResult 实例
         * @throws IllegalArgumentException 数据格式无效
         */
        fun fromTransportFormat(data: Map<String, Any>, key: SecretKey): CipherResult {
            return CipherResult(
                ciphertext = data["ciphertext"] as ByteArray,
                key = key,
                iv = data["iv"] as ByteArray,
                mode = data["mode"] as String,
                algorithm = data["algorithm"] as String,
                authTag = data["authTag"] as? ByteArray
            )
        }
    }
}
