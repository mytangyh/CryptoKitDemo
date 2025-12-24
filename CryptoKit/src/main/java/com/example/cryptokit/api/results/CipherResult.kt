package com.example.cryptokit.api.results

import com.example.cryptokit.util.SecureUtils
import java.io.Closeable
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * 对称加密结果
 * 
 * 实现Closeable接口，支持自动资源管理和敏感数据擦除
 * 
 * 使用示例：
 * ```kotlin
 * CryptoKit.aes().encrypt("data").use { result ->
 *     // 使用result
 * } // 自动擦除敏感数据
 * ```
 */
data class CipherResult(
    val ciphertext: ByteArray,
    val key: SecretKey,
    val iv: ByteArray,
    val mode: String,
    val algorithm: String,
    val authTag: ByteArray? = null
) : Closeable {
    
    // 标记是否已擦除
    @Volatile
    private var isWiped = false
    
    /**
     * 安全擦除敏感数据
     * 擦除密钥和IV
     */
    override fun close() {
        if (isWiped) return
        synchronized(this) {
            if (isWiped) return
            
            // 擦除IV
            SecureUtils.wipe(iv)
            
            // 擦除authTag
            SecureUtils.wipe(authTag)
            
            // 尝试擦除密钥（如果是SecretKeySpec）
            try {
                val keyBytes = key.encoded
                if (keyBytes != null) {
                    SecureUtils.wipe(keyBytes)
                }
            } catch (e: Exception) {
                // Keystore密钥可能不支持encoded
            }
            
            isWiped = true
        }
    }
    
    /**
     * 检查是否已被擦除
     */
    fun isCleared(): Boolean = isWiped
    
    /**
     * 验证结果有效性
     */
    fun validate(): Boolean {
        return !isWiped && 
               ciphertext.isNotEmpty() && 
               iv.isNotEmpty()
    }
    
    /**
     * 获取密钥字节（注意：调用方需负责擦除）
     */
    fun getKeyBytes(): ByteArray {
        check(!isWiped) { "CipherResult has been cleared" }
        return key.encoded ?: throw IllegalStateException("Key does not support encoding")
    }
    
    /**
     * 转为可序列化的格式（不包含密钥，需单独安全传输）
     */
    fun toTransportFormat(): Map<String, Any> {
        check(!isWiped) { "CipherResult has been cleared" }
        return mapOf(
            "ciphertext" to ciphertext,
            "iv" to iv,
            "mode" to mode,
            "algorithm" to algorithm,
            "authTag" to (authTag ?: byteArrayOf())
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as CipherResult
        // 使用恒定时间比较密文
        return SecureUtils.constantTimeEquals(ciphertext, other.ciphertext) &&
                key == other.key &&
                SecureUtils.constantTimeEquals(iv, other.iv) &&
                mode == other.mode &&
                algorithm == other.algorithm &&
                SecureUtils.constantTimeEquals(authTag ?: byteArrayOf(), other.authTag ?: byteArrayOf())
    }

    override fun hashCode(): Int {
        var result = ciphertext.contentHashCode()
        result = 31 * result + key.hashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + mode.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + (authTag?.contentHashCode() ?: 0)
        return result
    }
    
    companion object {
        /**
         * 从传输格式恢复（需要单独提供密钥）
         */
        fun fromTransportFormat(
            data: Map<String, Any>,
            key: SecretKey
        ): CipherResult {
            return CipherResult(
                ciphertext = data["ciphertext"] as ByteArray,
                key = key,
                iv = data["iv"] as ByteArray,
                mode = data["mode"] as String,
                algorithm = data["algorithm"] as String,
                authTag = (data["authTag"] as? ByteArray)?.takeIf { it.isNotEmpty() }
            )
        }
    }
}
