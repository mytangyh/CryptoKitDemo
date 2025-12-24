package com.example.cryptokit.api.builders

import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.exception.ValidationException
import com.example.cryptokit.util.CryptoLogger
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
) : BaseBuilder() {
    
    private val engine: StandardHashEngine
        get() = StandardHashEngine(algorithm)

    /**
     * 设置算法
     */
    fun algorithm(algorithm: String): HashBuilder = apply { 
        requireIn(algorithm.uppercase(), SUPPORTED_ALGORITHMS, "algorithm")
        this.algorithm = algorithm 
    }

    fun md5(): HashBuilder = apply { this.algorithm = "MD5" }
    fun sha1(): HashBuilder = apply { this.algorithm = "SHA-1" }
    fun sha256(): HashBuilder = apply { this.algorithm = "SHA-256" }
    fun sha384(): HashBuilder = apply { this.algorithm = "SHA-384" }
    fun sha512(): HashBuilder = apply { this.algorithm = "SHA-512" }

    /**
     * 计算摘要
     */
    fun digest(data: ByteArray): ByteArray {
        requireNotEmpty(data, "data")
        CryptoLogger.logHash(algorithm, data.size)
        return wrapCryptoException("Hash calculation") { engine.hash(data) }
    }
    
    fun digest(data: String): ByteArray {
        requireNotEmpty(data, "data")
        return digest(data.toByteArray(Charsets.UTF_8))
    }

    fun digestToHex(data: ByteArray): String = digest(data).joinToString("") { "%02x".format(it) }
    fun digestToHex(data: String): String = digestToHex(data.toByteArray(Charsets.UTF_8))

    /**
     * 计算HMAC
     */
    fun hmac(data: ByteArray, key: ByteArray): ByteArray {
        requireNotEmpty(data, "data")
        requireNotEmpty(key, "key")
        CryptoLogger.d("HMAC", "[$algorithm] Computing HMAC for ${data.size} bytes")
        return wrapCryptoException("HMAC calculation") { engine.hmac(data, key) }
    }
    
    fun hmac(data: String, key: ByteArray): ByteArray = hmac(data.toByteArray(Charsets.UTF_8), key)

    fun hmacToHex(data: ByteArray, key: ByteArray): String = 
        hmac(data, key).joinToString("") { "%02x".format(it) }
    fun hmacToHex(data: String, key: ByteArray): String = 
        hmacToHex(data.toByteArray(Charsets.UTF_8), key)

    /**
     * 计算流摘要（支持大文件）
     */
    fun digestStream(inputStream: InputStream): ByteArray = 
        wrapCryptoException("Stream hash calculation") { engine.hashStream(inputStream) }
    
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
