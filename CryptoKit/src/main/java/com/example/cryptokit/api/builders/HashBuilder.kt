package com.example.cryptokit.api.builders

import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.exception.CryptoException
import com.example.cryptokit.exception.ValidationException
import java.io.InputStream

/**
 * 哈希计算Builder
 * 
 * 金融级特性：
 * - 输入验证
 * - 类型化异常
 * - 支持多种算法
 */
class HashBuilder(
    private var algorithm: String = "SHA-256"
) {
    private val engine: StandardHashEngine
        get() = StandardHashEngine(algorithm)

    /**
     * 设置算法
     */
    fun algorithm(algorithm: String): HashBuilder = apply { 
        if (algorithm.uppercase() !in SUPPORTED_ALGORITHMS) {
            throw ValidationException("Unsupported hash algorithm: $algorithm, supported: $SUPPORTED_ALGORITHMS")
        }
        this.algorithm = algorithm 
    }

    fun md5(): HashBuilder = apply { this.algorithm = "MD5" }
    fun sha1(): HashBuilder = apply { this.algorithm = "SHA-1" }
    fun sha256(): HashBuilder = apply { this.algorithm = "SHA-256" }
    fun sha384(): HashBuilder = apply { this.algorithm = "SHA-384" }
    fun sha512(): HashBuilder = apply { this.algorithm = "SHA-512" }

    /**
     * 计算摘要
     * 
     * @throws ValidationException 输入验证失败
     * @throws CryptoException 计算失败
     */
    fun digest(data: ByteArray): ByteArray {
        if (data.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        try {
            return engine.hash(data)
        } catch (e: Exception) {
            throw CryptoException("Hash calculation failed: ${e.message}", e)
        }
    }
    
    fun digest(data: String): ByteArray {
        if (data.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        return digest(data.toByteArray(Charsets.UTF_8))
    }

    fun digestToHex(data: ByteArray): String = digest(data).joinToString("") { "%02x".format(it) }
    fun digestToHex(data: String): String = digestToHex(data.toByteArray(Charsets.UTF_8))

    /**
     * 计算HMAC
     * 
     * @throws ValidationException 输入验证失败
     * @throws CryptoException 计算失败
     */
    fun hmac(data: ByteArray, key: ByteArray): ByteArray {
        if (data.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (key.isEmpty()) {
            throw ValidationException("HMAC key cannot be empty")
        }
        try {
            return engine.hmac(data, key)
        } catch (e: Exception) {
            throw CryptoException("HMAC calculation failed: ${e.message}", e)
        }
    }
    
    fun hmac(data: String, key: ByteArray): ByteArray = hmac(data.toByteArray(Charsets.UTF_8), key)

    fun hmacToHex(data: ByteArray, key: ByteArray): String = 
        hmac(data, key).joinToString("") { "%02x".format(it) }
    fun hmacToHex(data: String, key: ByteArray): String = 
        hmacToHex(data.toByteArray(Charsets.UTF_8), key)

    /**
     * 计算流摘要（支持大文件）
     */
    fun digestStream(inputStream: InputStream): ByteArray {
        try {
            return engine.hashStream(inputStream)
        } catch (e: Exception) {
            throw CryptoException("Stream hash calculation failed: ${e.message}", e)
        }
    }
    
    /**
     * 获取当前算法的摘要长度（字节）
     */
    fun digestLength(): Int = engine.digestLength
    
    companion object {
        private val SUPPORTED_ALGORITHMS = listOf(
            "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
            "SHA-224", "SHA3-256", "SHA3-384", "SHA3-512"
        )
    }
}
