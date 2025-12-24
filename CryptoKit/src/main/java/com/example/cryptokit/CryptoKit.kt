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
 * # CryptoKit - Android 加密套件统一入口
 *
 * CryptoKit 是一个面向金融级应用的 Android 加密库，提供安全、易用、可扩展的加密能力。
 *
 * ## 特性
 *
 * - **零配置使用**：默认采用最安全的配置（AES-256-GCM、RSA-2048-OAEP）
 * - **金融级安全**：敏感数据自动擦除、恒定时间比较、线程安全
 * - **完整加密能力**：对称加密、非对称加密、混合加密、流式加密
 * - **Android Keystore 集成**：支持硬件级密钥保护
 * - **可扩展架构**：通过 [AlgorithmRegistry] 注册自定义算法
 *
 * ## 快速开始
 *
 * ### AES 加密（推荐）
 * ```kotlin
 * // 加密
 * val result = CryptoKit.aes().encrypt("Hello, World!")
 *
 * // 解密（使用 use 块自动清除敏感数据）
 * result.use { r ->
 *     val plaintext = CryptoKit.aes().decrypt(r)
 * }
 * ```
 *
 * ### RSA 加密
 * ```kotlin
 * val keyPair = CryptoKit.rsa().generateKeyPair()
 * val encrypted = CryptoKit.rsa()
 *     .publicKey(keyPair.public)
 *     .encrypt("Secret")
 * val decrypted = CryptoKit.rsa()
 *     .privateKey(keyPair.private)
 *     .decryptToString(encrypted)
 * ```
 *
 * ### 混合加密（大数据）
 * ```kotlin
 * val keyPair = CryptoKit.rsa().generateKeyPair()
 * val result = CryptoKit.hybrid()
 *     .publicKey(keyPair.public)
 *     .encrypt(largeData)
 * ```
 *
 * ### 流式加密（超大文件）
 * ```kotlin
 * val key = CryptoKit.aes().generateKey()
 * val iv = CryptoKit.secureRandom(16)
 * CryptoKit.stream.encrypt(inputStream, outputStream, key, iv, "CBC")
 * ```
 *
 * ### 数字签名
 * ```kotlin
 * val keyPair = CryptoKit.rsa().generateKeyPair()
 * val signature = CryptoKit.rsa()
 *     .privateKey(keyPair.private)
 *     .sign("data")
 * val isValid = CryptoKit.rsa()
 *     .publicKey(keyPair.public)
 *     .verify("data", signature)
 * ```
 *
 * ### Android Keystore
 * ```kotlin
 * val key = CryptoKit.keyManager.generateAESKeyInKeystore(
 *     "my_key",
 *     256,
 *     KeyStoreOptions.financialGrade()
 * )
 * ```
 *
 * ## 安全建议
 *
 * 1. 使用 [CipherResult.use] 块确保敏感数据自动擦除
 * 2. 生产环境使用 AES-256-GCM（默认配置）
 * 3. RSA 密钥至少 2048 位
 * 4. 使用 Android Keystore 存储长期密钥
 * 5. 启用 StrongBox 硬件安全模块（如果可用）
 *
 * @since 1.0.0
 * @see AESBuilder
 * @see RSABuilder
 * @see ECCBuilder
 * @see HybridBuilder
 * @see KeyManager
 */
object CryptoKit {

    // ==================== 对称加密 ====================

    /**
     * 创建 AES 加密 Builder
     *
     * AES 是推荐的对称加密算法，默认使用 AES-256-GCM 模式。
     *
     * ## 支持的配置
     * - **模式**: GCM（默认，推荐）、CBC、CTR
     * - **密钥长度**: 128、192、256 位
     * - **附加认证数据 (AAD)**: 仅 GCM 模式支持
     *
     * ## 示例
     * ```kotlin
     * // 使用默认配置（AES-256-GCM）
     * val result = CryptoKit.aes().encrypt("data")
     *
     * // 自定义配置
     * val result = CryptoKit.aes()
     *     .cbc()           // 使用 CBC 模式
     *     .keySize(192)    // 192 位密钥
     *     .encrypt("data")
     * ```
     *
     * @return [AESBuilder] 实例
     * @see AESBuilder
     */
    fun aes(): AESBuilder = AESBuilder()

    /**
     * 创建 3DES 加密 Builder
     *
     * **⚠️ 警告**: 3DES 已不推荐用于新项目，仅用于兼容旧系统。
     * 新项目请使用 [aes]。
     *
     * ## 示例
     * ```kotlin
     * val result = CryptoKit.tripleDes().cbc().encrypt("data")
     * ```
     *
     * @return [TripleDESBuilder] 实例
     * @see TripleDESBuilder
     */
    fun tripleDes(): TripleDESBuilder = TripleDESBuilder()

    // ==================== 非对称加密 ====================

    /**
     * 创建 RSA 加密 Builder
     *
     * RSA 支持加密、解密和数字签名。默认使用 RSA-2048 和 OAEP 填充。
     *
     * ## 支持的配置
     * - **密钥长度**: 1024、2048、3072、4096 位
     * - **填充方案**: OAEP-SHA256（默认）、OAEP-SHA1、PKCS1
     * - **签名算法**: SHA256withRSA（默认）
     *
     * ## 示例
     * ```kotlin
     * val keyPair = CryptoKit.rsa().generateKeyPair()
     *
     * // 加密
     * val ciphertext = CryptoKit.rsa()
     *     .publicKey(keyPair.public)
     *     .encrypt("secret")
     *
     * // 签名
     * val signature = CryptoKit.rsa()
     *     .privateKey(keyPair.private)
     *     .sign("data")
     * ```
     *
     * @return [RSABuilder] 实例
     * @see RSABuilder
     */
    fun rsa(): RSABuilder = RSABuilder()

    /**
     * 创建 ECC (椭圆曲线) 加密 Builder
     *
     * ECC 支持 ECDSA 签名和 ECDH 密钥协商。默认使用 P-256 曲线。
     *
     * ## 支持的曲线
     * - P-256 / secp256r1（默认）
     * - P-384 / secp384r1
     * - P-521 / secp521r1
     *
     * ## 示例
     * ```kotlin
     * val keyPair = CryptoKit.ecc().p256().generateKeyPair()
     *
     * // ECDSA 签名
     * val signature = CryptoKit.ecc()
     *     .privateKey(keyPair.private)
     *     .sign("data")
     *
     * // ECDH 密钥协商
     * val sharedSecret = CryptoKit.ecc()
     *     .privateKey(myKeyPair.private)
     *     .deriveSharedSecret(peerPublicKey)
     * ```
     *
     * @return [ECCBuilder] 实例
     * @see ECCBuilder
     */
    fun ecc(): ECCBuilder = ECCBuilder()

    // ==================== 组合加密 ====================

    /**
     * 创建混合加密 Builder
     *
     * 混合加密使用 RSA 加密 AES 密钥，然后使用 AES 加密实际数据。
     * 适用于加密大量数据，比纯 RSA 更高效且无长度限制。
     *
     * ## 工作原理
     * 1. 随机生成 AES 密钥
     * 2. 使用 AES-GCM 加密数据
     * 3. 使用 RSA 加密 AES 密钥
     * 4. 返回加密的密钥、密文和 IV
     *
     * ## 示例
     * ```kotlin
     * val keyPair = CryptoKit.rsa().generateKeyPair()
     *
     * // 加密
     * val result = CryptoKit.hybrid()
     *     .publicKey(keyPair.public)
     *     .encrypt(largeData)
     *
     * // 解密
     * val plaintext = CryptoKit.hybrid()
     *     .privateKey(keyPair.private)
     *     .decrypt(result)
     * ```
     *
     * @return [HybridBuilder] 实例
     * @see HybridBuilder
     */
    fun hybrid(): HybridBuilder = HybridBuilder()

    // ==================== 流式加密 ====================

    /**
     * 流式加密工具
     *
     * 用于加密/解密大文件或流数据，避免内存溢出。
     *
     * **注意**: 流式加密仅支持 CBC 和 CTR 模式，GCM 模式需要完整数据计算认证标签。
     *
     * ## 示例
     * ```kotlin
     * val key = CryptoKit.aes().generateKey()
     * val iv = CryptoKit.secureRandom(16)
     *
     * // 加密文件
     * FileInputStream("input.txt").use { input ->
     *     FileOutputStream("output.enc").use { output ->
     *         CryptoKit.stream.encrypt(input, output, key, iv, "CBC")
     *     }
     * }
     * ```
     *
     * @see StreamCipher
     */
    object stream {
        /**
         * 加密流
         *
         * @param inputStream 明文输入流
         * @param outputStream 密文输出流
         * @param key AES 密钥
         * @param iv 初始化向量（CBC 使用 16 字节）
         * @param mode 加密模式，"CBC" 或 "CTR"
         * @return 处理的字节数
         * @throws com.example.cryptokit.exception.EncryptionException 加密失败
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
         *
         * @param inputStream 密文输入流
         * @param outputStream 明文输出流
         * @param key AES 密钥
         * @param iv 初始化向量
         * @param mode 加密模式，"CBC" 或 "CTR"
         * @return 处理的字节数
         * @throws com.example.cryptokit.exception.DecryptionException 解密失败
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
         *
         * @param outputStream 底层输出流
         * @param key AES 密钥
         * @param iv 初始化向量
         * @param mode 加密模式
         * @return CipherOutputStream
         */
        fun createEncryptOutputStream(
            outputStream: OutputStream,
            key: SecretKey,
            iv: ByteArray,
            mode: String = "CBC"
        ) = StreamCipher.createEncryptOutputStream(outputStream, key, iv, mode)
        
        /**
         * 创建解密输入流
         *
         * @param inputStream 底层输入流
         * @param key AES 密钥
         * @param iv 初始化向量
         * @param mode 加密模式
         * @return CipherInputStream
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
     * 创建哈希计算 Builder
     *
     * 支持 MD5、SHA-1、SHA-256、SHA-384、SHA-512 等算法。
     *
     * ## 示例
     * ```kotlin
     * // SHA-256 哈希
     * val hash = CryptoKit.hash().digest("data")
     * val hashHex = CryptoKit.hash().digestToHex("data")
     *
     * // HMAC
     * val hmac = CryptoKit.hash().hmac("data", key)
     * ```
     *
     * @param algorithm 哈希算法，默认 "SHA-256"
     * @return [HashBuilder] 实例
     * @see HashBuilder
     */
    fun hash(algorithm: String = "SHA-256"): HashBuilder = HashBuilder(algorithm)

    // ==================== 编码 ====================

    /**
     * 编码工具
     *
     * 提供 Base64 和 Hex 编码/解码功能。
     *
     * ## 示例
     * ```kotlin
     * val base64 = CryptoKit.encode.toBase64(data)
     * val hex = CryptoKit.encode.toHex(data)
     *
     * val decoded = CryptoKit.encode.fromBase64(base64)
     * ```
     */
    object encode {
        /** Base64 编码（标准） */
        fun toBase64(data: ByteArray): String = Base64Encoder.standard().encode(data)
        /** Base64 编码（URL 安全） */
        fun toBase64Url(data: ByteArray): String = Base64Encoder.urlSafe().encode(data)
        /** Base64 编码（无换行） */
        fun toBase64NoWrap(data: ByteArray): String = Base64Encoder.noWrap().encode(data)
        /** 十六进制编码 */
        fun toHex(data: ByteArray): String = HexEncoder.getInstance().encode(data)

        /** Base64 解码（标准） */
        fun fromBase64(encoded: String): ByteArray = Base64Encoder.standard().decode(encoded)
        /** Base64 解码（URL 安全） */
        fun fromBase64Url(encoded: String): ByteArray = Base64Encoder.urlSafe().decode(encoded)
        /** 十六进制解码 */
        fun fromHex(encoded: String): ByteArray = HexEncoder.getInstance().decode(encoded)
    }

    // ==================== 安全工具 ====================

    /**
     * 安全工具
     *
     * 提供敏感数据安全擦除和恒定时间比较等安全功能。
     *
     * ## 示例
     * ```kotlin
     * // 安全擦除
     * CryptoKit.secure.wipe(sensitiveBytes)
     *
     * // 恒定时间比较（防时序攻击）
     * val isEqual = CryptoKit.secure.constantTimeEquals(hash1, hash2)
     *
     * // 安全作用域
     * CryptoKit.secure.withSecureBytes(key) { keyBytes ->
     *     // 使用 keyBytes
     * } // 自动擦除
     * ```
     */
    object secure {
        /**
         * 安全擦除字节数组
         *
         * 先用随机数覆盖，再用零覆盖，防止内存残留分析。
         *
         * @param data 要擦除的字节数组
         */
        fun wipe(data: ByteArray?) = SecureUtils.wipe(data)
        
        /**
         * 安全擦除字符数组（适用于密码）
         *
         * @param data 要擦除的字符数组
         */
        fun wipe(data: CharArray?) = SecureUtils.wipe(data)
        
        /**
         * 恒定时间比较（防止时序攻击）
         *
         * 无论内容差异在哪个位置，比较时间都相同。
         *
         * @param a 第一个字节数组
         * @param b 第二个字节数组
         * @return 是否相等
         */
        fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean = 
            SecureUtils.constantTimeEquals(a, b)
        
        /**
         * 安全作用域，自动擦除
         *
         * @param data 敏感数据
         * @param block 使用数据的代码块
         * @return 代码块返回值
         */
        inline fun <T> withSecureBytes(data: ByteArray, block: (ByteArray) -> T): T =
            SecureUtils.withSecureBytes(data, block)
    }

    // ==================== 密钥管理 ====================

    /**
     * Android Keystore 密钥管理器
     *
     * 提供硬件级别的密钥保护，密钥存储在安全元件中，不可导出。
     *
     * ## 示例
     * ```kotlin
     * // 生成 AES 密钥
     * val key = CryptoKit.keyManager.generateAESKeyInKeystore("my_key")
     *
     * // 使用金融级安全配置
     * val key = CryptoKit.keyManager.generateAESKeyInKeystore(
     *     "payment_key",
     *     256,
     *     KeyStoreOptions.financialGrade()
     * )
     *
     * // 列出所有密钥
     * val aliases = CryptoKit.keyManager.listAliases()
     * ```
     *
     * @see KeyManager
     * @see com.example.cryptokit.keymanager.KeyStoreOptions
     */
    val keyManager: KeyManager get() = KeyManagerImpl.instance

    // ==================== 算法注册 ====================

    /**
     * 算法注册表
     *
     * 用于扩展自定义加密算法。
     *
     * ## 示例
     * ```kotlin
     * // 注册自定义算法
     * CryptoKit.registry.registerSymmetricCipher("MY-AES") {
     *     MyCustomAESCipher()
     * }
     *
     * // 获取算法
     * val cipher = CryptoKit.registry.getSymmetricCipher("MY-AES")
     *
     * // 列出所有已注册算法
     * val algorithms = CryptoKit.registry.listSymmetricCiphers()
     * ```
     *
     * @see AlgorithmRegistry
     */
    val registry: AlgorithmRegistry get() = AlgorithmRegistry

    // ==================== 拦截器 ====================

    /**
     * 拦截器链管理
     *
     * 用于日志记录、性能监控等横切关注点。
     *
     * @see com.example.cryptokit.interceptor.InterceptorChain
     */
    val interceptors: com.example.cryptokit.interceptor.InterceptorChain
        get() = com.example.cryptokit.interceptor.InterceptorChain

    /**
     * 启用调试模式
     *
     * 同时启用日志记录和性能监控。
     */
    fun enableDebugMode() {
        interceptors.enableDebugMode()
    }

    /**
     * 启用日志记录
     *
     * @param tag 日志标签，默认 "CryptoKit"
     */
    fun enableLogging(tag: String = "CryptoKit") {
        interceptors.enableLogging(tag)
    }

    /**
     * 启用性能监控
     *
     * @param warningThresholdMs 慢操作警告阈值（毫秒），默认 100ms
     */
    fun enablePerformanceMonitoring(warningThresholdMs: Long = 100) {
        interceptors.enablePerformanceMonitoring(warningThresholdMs)
    }

    /**
     * 禁用所有拦截器
     */
    fun disableInterceptors() {
        interceptors.disable()
        interceptors.clearInterceptors()
    }

    // ==================== 快捷方法 ====================

    /**
     * 快速 SHA-256 哈希
     *
     * @param data 输入数据
     * @return 十六进制哈希值
     */
    fun sha256(data: String): String = hash("SHA-256").digestToHex(data)
    
    /**
     * 快速 SHA-256 哈希
     *
     * @param data 输入数据
     * @return 哈希字节数组
     */
    fun sha256(data: ByteArray): ByteArray = hash("SHA-256").digest(data)

    /**
     * 快速 SHA-512 哈希
     *
     * @param data 输入数据
     * @return 十六进制哈希值
     */
    fun sha512(data: String): String = hash("SHA-512").digestToHex(data)
    
    /**
     * 快速 SHA-512 哈希
     *
     * @param data 输入数据
     * @return 哈希字节数组
     */
    fun sha512(data: ByteArray): ByteArray = hash("SHA-512").digest(data)

    /**
     * 快速 MD5 哈希
     *
     * **⚠️ 警告**: MD5 已不安全，仅用于非安全场景（如文件校验）。
     *
     * @param data 输入数据
     * @return 十六进制哈希值
     */
    fun md5(data: String): String = hash("MD5").digestToHex(data)
    
    /**
     * 快速 MD5 哈希
     *
     * @param data 输入数据
     * @return 哈希字节数组
     */
    fun md5(data: ByteArray): ByteArray = hash("MD5").digest(data)

    /**
     * 生成安全随机字节数组
     *
     * 使用 [java.security.SecureRandom] 生成密码学安全的随机数。
     *
     * @param length 字节数
     * @return 随机字节数组
     */
    fun secureRandom(length: Int): ByteArray = SecureRandomUtil.nextBytes(length)

    /**
     * 生成随机 UUID 字符串
     *
     * @return UUID 字符串，如 "550e8400-e29b-41d4-a716-446655440000"
     */
    fun randomUUID(): String = java.util.UUID.randomUUID().toString()

    /**
     * 计算 HMAC
     *
     * @param data 输入数据
     * @param key HMAC 密钥
     * @param algorithm 哈希算法，默认 "SHA-256"
     * @return HMAC 字节数组
     */
    fun hmac(data: String, key: ByteArray, algorithm: String = "SHA-256"): ByteArray =
        hash(algorithm).hmac(data, key)

    /**
     * 计算 HMAC（返回十六进制字符串）
     *
     * @param data 输入数据
     * @param key HMAC 密钥
     * @param algorithm 哈希算法，默认 "SHA-256"
     * @return 十六进制 HMAC
     */
    fun hmacToHex(data: String, key: ByteArray, algorithm: String = "SHA-256"): String =
        hash(algorithm).hmacToHex(data, key)

    /**
     * PBKDF2 密钥派生
     *
     * 从密码派生加密密钥，适用于基于密码的加密场景。
     *
     * ## 示例
     * ```kotlin
     * val salt = CryptoKit.secureRandom(16)
     * val key = CryptoKit.deriveKey(
     *     password = "myPassword",
     *     salt = salt,
     *     iterations = 100000,  // 生产环境建议 >= 100000
     *     keyLength = 256
     * )
     * ```
     *
     * @param password 密码
     * @param salt 盐值（至少 16 字节）
     * @param iterations 迭代次数，默认 10000（生产环境建议 >= 100000）
     * @param keyLength 派生密钥长度（位），默认 256
     * @param algorithm 哈希算法，默认 "SHA-256"
     * @return 派生的密钥字节数组
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
