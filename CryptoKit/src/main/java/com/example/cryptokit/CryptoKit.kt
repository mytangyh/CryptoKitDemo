package com.example.cryptokit

import com.example.cryptokit.api.builders.*
import com.example.cryptokit.api.extensions.toHex
import com.example.cryptokit.core.encoding.Base64Encoder
import com.example.cryptokit.core.encoding.HexEncoder
import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.core.stream.StreamCipher
import com.example.cryptokit.keymanager.KeyManager
import com.example.cryptokit.keymanager.KeyManagerImpl
import com.example.cryptokit.registry.AlgorithmRegistry
import com.example.cryptokit.util.SecureRandomUtil
import com.example.cryptokit.util.SecureUtils
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.SecretKey

/**
 * CryptoKit - Android加密套件统一入口
 * 
 * 金融级特性：
 * - 线程安全
 * - 敏感数据自动擦除
 * - 完善的异常处理
 * - 流式加密支持
 * - 可扩展算法注册
 *
 * 使用示例:
 * ```kotlin
 * // 零配置AES加密
 * CryptoKit.aes().encrypt("Hello, World!").use { result ->
 *     val plaintext = CryptoKit.aes().decrypt(result)
 * }
 *
 * // RSA加密
 * val keyPair = CryptoKit.rsa().generateKeyPair()
 * val encrypted = CryptoKit.rsa().publicKey(keyPair.public).encrypt("Secret")
 *
 * // 混合加密（大数据）
 * val hybridResult = CryptoKit.hybrid().publicKey(publicKey).encrypt(largeData)
 *
 * // 流式加密（超大文件）
 * CryptoKit.stream.encryptFile(inputStream, outputStream, key, iv)
 *
 * // 哈希
 * val hash = CryptoKit.hash().digest("Hello, World!")
 * ```
 */
object CryptoKit {

    // ==================== 对称加密 ====================

    /**
     * AES加密（推荐使用GCM模式）
     * 默认配置：AES-256-GCM，自动生成密钥和IV
     */
    fun aes(): AESBuilder = AESBuilder()

    /**
     * 3DES加密（兼容旧系统）
     * 默认配置：3DES-CBC-PKCS5Padding
     */
    fun tripleDes(): TripleDESBuilder = TripleDESBuilder()

    // ==================== 非对称加密 ====================

    /**
     * RSA加密/签名
     * 默认配置：RSA-2048，OAEP填充
     */
    fun rsa(): RSABuilder = RSABuilder()

    /**
     * ECC加密/签名
     * 默认配置：P-256曲线
     */
    fun ecc(): ECCBuilder = ECCBuilder()

    // ==================== 组合加密 ====================

    /**
     * 混合加密（RSA+AES）
     * 适用于加密大量数据
     */
    fun hybrid(): HybridBuilder = HybridBuilder()

    // ==================== 流式加密 ====================

    /**
     * 流式加密工具（适用于大文件）
     */
    object stream {
        /**
         * 加密流
         * 注意：使用CBC或CTR模式，GCM不支持流式处理
         */
        fun encrypt(
            inputStream: InputStream,
            outputStream: OutputStream,
            key: SecretKey,
            iv: ByteArray,
            mode: String = "CBC"
        ): Long = StreamCipher.encryptStream(inputStream, outputStream, key, iv, mode)

        /**
         * 解密流
         */
        fun decrypt(
            inputStream: InputStream,
            outputStream: OutputStream,
            key: SecretKey,
            iv: ByteArray,
            mode: String = "CBC"
        ): Long = StreamCipher.decryptStream(inputStream, outputStream, key, iv, mode)
        
        /**
         * 创建加密输出流
         */
        fun createEncryptOutputStream(
            outputStream: OutputStream,
            key: SecretKey,
            iv: ByteArray,
            mode: String = "CBC"
        ) = StreamCipher.createEncryptOutputStream(outputStream, key, iv, mode)
        
        /**
         * 创建解密输入流
         */
        fun createDecryptInputStream(
            inputStream: InputStream,
            key: SecretKey,
            iv: ByteArray,
            mode: String = "CBC"
        ) = StreamCipher.createDecryptInputStream(inputStream, key, iv, mode)
    }

    // ==================== 哈希 ====================

    /**
     * 哈希计算
     * 默认配置：SHA-256
     */
    fun hash(algorithm: String = "SHA-256"): HashBuilder = HashBuilder(algorithm)

    // ==================== 编码 ====================

    /**
     * 编码工具
     */
    object encode {
        fun toBase64(data: ByteArray): String = Base64Encoder.standard().encode(data)
        fun toBase64Url(data: ByteArray): String = Base64Encoder.urlSafe().encode(data)
        fun toBase64NoWrap(data: ByteArray): String = Base64Encoder.noWrap().encode(data)
        fun toHex(data: ByteArray): String = HexEncoder.getInstance().encode(data)

        fun fromBase64(encoded: String): ByteArray = Base64Encoder.standard().decode(encoded)
        fun fromBase64Url(encoded: String): ByteArray = Base64Encoder.urlSafe().decode(encoded)
        fun fromHex(encoded: String): ByteArray = HexEncoder.getInstance().decode(encoded)
    }

    // ==================== 安全工具 ====================

    /**
     * 安全工具
     */
    object secure {
        /**
         * 安全擦除字节数组
         */
        fun wipe(data: ByteArray?) = SecureUtils.wipe(data)
        
        /**
         * 安全擦除字符数组（密码）
         */
        fun wipe(data: CharArray?) = SecureUtils.wipe(data)
        
        /**
         * 恒定时间比较（防时序攻击）
         */
        fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean = 
            SecureUtils.constantTimeEquals(a, b)
        
        /**
         * 安全作用域（自动擦除）
         */
        inline fun <T> withSecureBytes(data: ByteArray, block: (ByteArray) -> T): T =
            SecureUtils.withSecureBytes(data, block)
    }

    // ==================== 密钥管理 ====================

    /**
     * 密钥管理器（Android Keystore）
     */
    val keyManager: KeyManager get() = KeyManagerImpl.instance

    // ==================== 算法注册 ====================

    /**
     * 算法注册表（用于扩展自定义算法）
     */
    val registry: AlgorithmRegistry get() = AlgorithmRegistry

    // ==================== 拦截器 ====================

    /**
     * 拦截器链管理
     */
    val interceptors: com.example.cryptokit.interceptor.InterceptorChain
        get() = com.example.cryptokit.interceptor.InterceptorChain

    /**
     * 启用调试模式（日志+性能监控）
     */
    fun enableDebugMode() {
        interceptors.enableDebugMode()
    }

    /**
     * 启用日志
     */
    fun enableLogging(tag: String = "CryptoKit") {
        interceptors.enableLogging(tag)
    }

    /**
     * 启用性能监控
     */
    fun enablePerformanceMonitoring(warningThresholdMs: Long = 100) {
        interceptors.enablePerformanceMonitoring(warningThresholdMs)
    }

    /**
     * 禁用拦截器
     */
    fun disableInterceptors() {
        interceptors.disable()
        interceptors.clearInterceptors()
    }

    // ==================== 快捷方法 ====================

    /**
     * 快速SHA-256哈希
     */
    fun sha256(data: String): String = hash("SHA-256").digestToHex(data)
    fun sha256(data: ByteArray): ByteArray = hash("SHA-256").digest(data)

    /**
     * 快速SHA-512哈希
     */
    fun sha512(data: String): String = hash("SHA-512").digestToHex(data)
    fun sha512(data: ByteArray): ByteArray = hash("SHA-512").digest(data)

    /**
     * 快速MD5哈希（仅用于非安全场景）
     */
    fun md5(data: String): String = hash("MD5").digestToHex(data)
    fun md5(data: ByteArray): ByteArray = hash("MD5").digest(data)

    /**
     * 生成安全随机数
     */
    fun secureRandom(length: Int): ByteArray = SecureRandomUtil.nextBytes(length)

    /**
     * 生成随机UUID字符串
     */
    fun randomUUID(): String = java.util.UUID.randomUUID().toString()

    /**
     * 计算HMAC
     */
    fun hmac(data: String, key: ByteArray, algorithm: String = "SHA-256"): ByteArray =
        hash(algorithm).hmac(data, key)

    /**
     * 计算HMAC（返回十六进制字符串）
     */
    fun hmacToHex(data: String, key: ByteArray, algorithm: String = "SHA-256"): String =
        hash(algorithm).hmacToHex(data, key)

    /**
     * 密钥派生（PBKDF2）
     */
    fun deriveKey(
        password: String,
        salt: ByteArray,
        iterations: Int = 10000,
        keyLength: Int = 256,
        algorithm: String = "SHA-256"
    ): ByteArray = SecureUtils.withSecurePassword(password.toCharArray()) { pwd ->
        StandardHashEngine(algorithm).deriveKey(pwd, salt, iterations, keyLength).encoded
    }

    // ==================== 版本信息 ====================

    /**
     * 库版本号
     */
    const val VERSION = "1.0.0"

    /**
     * 库版本名
     */
    const val VERSION_NAME = "CryptoKit Financial Grade"
}
